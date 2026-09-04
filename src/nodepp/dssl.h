/*
 * Copyright 2023 The Nodepp Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/NodeppOfficial/nodepp/blob/main/LICENSE
 */

/*────────────────────────────────────────────────────────────────────────────*/

#ifndef NODEPP_DSSL
#define NODEPP_DSSL
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

/*────────────────────────────────────────────────────────────────────────────*/

#include "initializer.h"
#include "crypto.h"

#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl_cookie.h"

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp { class dssl_t {
protected:

    using onSNI = function_t<dssl_t*,string_t>;

    enum STATE : uchar { 
         DSSL_STATE_UNKNOWN   = 0b00000000,
         DSSL_STATE_USED      = 0b00000010,
         DSSL_STATE_CONNECTED = 0b00000001,
         DSSL_STATE_SERVER    = 0b10000000
    };

    struct NODE {

        mbedtls_ssl_context      ssl;
        mbedtls_ssl_config       conf;
        mbedtls_x509_crt         cert;
        mbedtls_pk_context       pkey;
        mbedtls_entropy_context  entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_ssl_cookie_ctx   cookie_ctx;
        
        ptr_t<onSNI> sni ; uchar state = 0;
        string_t key_path, crt_path;

        NODE() {
            mbedtls_ssl_init       (&ssl) ;
            mbedtls_ssl_config_init(&conf);
            mbedtls_x509_crt_init  (&cert);
            mbedtls_pk_init        (&pkey);
            mbedtls_entropy_init   (&entropy);
            mbedtls_ctr_drbg_init  (&ctr_drbg);
            mbedtls_ssl_cookie_init(&cookie_ctx);
        }

       ~NODE() {
            mbedtls_ssl_free       (&ssl) ;
            mbedtls_ssl_config_free(&conf);
            mbedtls_x509_crt_free  (&cert);
            mbedtls_pk_free        (&pkey);
            mbedtls_entropy_free   (&entropy);
            mbedtls_ctr_drbg_free  (&ctr_drbg);
            mbedtls_ssl_cookie_free(&cookie_ctx);
        }

    };  ptr_t<NODE> obj;

    /*─······································································─*/
    
    bool is_connected() const noexcept { return obj->state & STATE::DSSL_STATE_CONNECTED; }

    bool    is_server() const noexcept { return obj->state & STATE::DSSL_STATE_SERVER; }

    bool is_available() const noexcept { return obj->state & STATE::DSSL_STATE_USED; }

    /*─······································································─*/

    static int bio_write( void *b, const uchar *buf, size_t len ) {
    if( b==nullptr ){ return -1; }

        auto stream = (socket_t*)b;
    //  auto nbuf   = stream->get_buffer_data( );
        auto nlen   = min( (ulong)len, stream->get_buffer_size() );

        if( stream->is_closed() ){ return -1; }
        int c = stream->socket_t::__write( (char*)buf, nlen ); 

        if  ( c<=0 ){
        if  ( stream->socket_t::is_waiting() )
            { return MBEDTLS_ERR_SSL_WANT_WRITE; }
        else{ stream->socket_t::stop(); return -1; }}

    return c; }

    static int bio_read( void *b, uchar *buf, size_t len ) {
    if( b==nullptr ){ return -1; }

        auto stream = (socket_t*) b;
        auto nbuf   = buf; // stream->get_buffer_data( );
        auto nlen   = min( (ulong)len, stream->get_buffer_size() );

        if( stream->is_closed() ){ return -1; }
        int c = stream->socket_t::__read( nbuf, nlen );

    //  if  ( c> 0 ){ memcpy( buf, nbuf, nlen ); }

        if  ( c<=0 ){
        if  ( stream->socket_t::is_waiting() )
            { return MBEDTLS_ERR_SSL_WANT_READ; }
        else{ stream->socket_t::stop(); return -1; }}

    return c; }

    /*─······································································─*/

    template< class T >
    int is_blocked( T* stream, int c ) const noexcept { 
    if( c<=0 && !stream->is_closed() ){

        if( c==MBEDTLS_ERR_SSL_WANT_WRITE ||
            c==MBEDTLS_ERR_SSL_WANT_READ
        ) { return 1; }

    } return stream->is_closed() ? -1 : c; }

    /*─······································································─*/

    static int sni_callback( void *arg, mbedtls_ssl_context *ssl, const uchar *name, size_t len ) {
        if( name==nullptr || ssl==nullptr || arg==nullptr || len==0 ){ return 0; }
        
        onSNI func = *((onSNI*)arg); 

        string_t servername((char*)name, (ulong)len);
        dssl_t* new_ssl_obj = func( servername );
        
        if( new_ssl_obj != nullptr ){ 
            return mbedtls_ssl_set_hs_own_cert( 
                ssl, &new_ssl_obj->obj->cert, 
                /**/ &new_ssl_obj->obj->pkey 
        ); }

    return 0; }

    /*─······································································─*/

    int configure_context( int mode ) { 
    int x = 1; 

        mbedtls_ssl_config_defaults(&obj->conf, mode & STATE::SSL_STATE_SERVER ? 
                                     MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM, 
                                     MBEDTLS_SSL_PRESET_DEFAULT
        );

        mbedtls_ssl_conf_rng(&obj->conf, mbedtls_ctr_drbg_random, &obj->ctr_drbg);

        if( mode & STATE::SSL_STATE_SERVER ) {
            
            if( obj->cert != nullptr ) {
            if( mbedtls_ssl_conf_own_cert(&obj->conf, &obj->cert, &obj->pkey) != 0 ) 
              { return -1; } }

            elif( !obj->crt_path.empty() && !obj->key_path.empty() ) {
                
                if( mbedtls_x509_crt_parse_file(&obj->cert, obj->crt_path.get()) != 0 ){ return -1; }
                if( mbedtls_pk_parse_keyfile(&obj->pkey, obj->key_path.get(), NULL, mbedtls_ctr_drbg_random, &obj->ctr_drbg ) != 0 
                ) { return -1; }
                if( mbedtls_ssl_conf_own_cert(&obj->conf, &obj->cert, &obj->pkey) != 0 ){ return -1; }

            } else { return -1; }

            mbedtls_ssl_conf_authmode(&obj->conf, MBEDTLS_SSL_VERIFY_NONE);
            mbedtls_ssl_cookie_setup     (&obj->cookie_ctx, mbedtls_ctr_drbg_random, &obj->ctr_drbg);
            mbedtls_ssl_conf_dtls_cookies(&obj->conf, 
                                           mbedtls_ssl_cookie_write, 
                                           mbedtls_ssl_cookie_check, 
                                          &obj->cookie_ctx);

            if( obj->cert.next != nullptr ) {
                mbedtls_ssl_conf_ca_chain(&obj->conf, obj->cert.next, NULL);
            }

            if( obj->sni != nullptr ) {
                mbedtls_ssl_conf_sni(&obj->conf, sni_callback, obj->sni.get());
            }

        }

        // mbedtls_ssl_conf_min_version(&obj->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

        return 1; 
    }

    /*─······································································─*/

public:

    dssl_t() : obj( new NODE() ) {
    NODEPP_CRYPTO_INITIALIZATOR();
        mbedtls_ctr_drbg_seed(&obj->ctr_drbg, mbedtls_entropy_func, &obj->entropy, NULL, 0);
        obj->state = STATE::DSSL_STATE_USED;
    }

    dssl_t( const string_t& key, const string_t& cert ) : obj( new NODE() ) {
    NODEPP_CRYPTO_INITIALIZATOR();
        mbedtls_ctr_drbg_seed(&obj->ctr_drbg, mbedtls_entropy_func, &obj->entropy, NULL, 0);
        obj->key_path = key; obj->crt_path = cert;
        obj->state = STATE::DSSL_STATE_USED;
    }

    dssl_t( dssl_t& xtc, int /*unused*/ ) : obj( new NODE() ) { 
    NODEPP_CRYPTO_INITIALIZATOR();
        mbedtls_ctr_drbg_seed(&obj->ctr_drbg, mbedtls_entropy_func, &obj->entropy, NULL, 0);
        mbedtls_ssl_setup(&obj->ssl, &xtc.obj->conf);
        obj->state = STATE::DSSL_STATE_USED; obj->state = xtc.obj->state;
    }

    /*─······································································─*/

    int create_server() { return configure_context( STATE::SSL_STATE_SERVER ); }

    int create_client() { return configure_context( 0x00 ); }
    
    /*─······································································─*/

    void set_password( const char* /*pass*/ ) const noexcept {
    //   if( !is_available() ){ return; }
    //   SSL_CTX_set_default_passwd_cb( obj->ctx, &SNI_CLB );
    //   SSL_CTX_set_default_passwd_cb_userdata( obj->ctx, (void*)pass );
    }

    int set_hostname( const string_t& name ) const noexcept {
        if( !is_available() ){ return -1; }
        return mbedtls_ssl_set_hostname( &obj->ssl, name.data() );
    }

    string_t get_hostname() const noexcept {
        if( !is_available() || obj == nullptr ){ return nullptr; }
        return obj->ssl.hostname;
    }

    /*─······································································─*/

    template<class T> int _connect( T* stream ) const noexcept {
        if( is_connected() ){ return 1; }

        mbedtls_ssl_set_bio( &obj->ssl, (void*)stream, bio_write, bio_read, NULL );
        mbedtls_ssl_set_client_transport_id( &obj->ssl, (const uchar*)&obj->ssl, sizeof(void*) );

        int c = mbedtls_ssl_handshake( &obj->ssl ); 
        
        if( c==MBEDTLS_ERR_SSL_WANT_WRITE ||
            c==MBEDTLS_ERR_SSL_WANT_READ
        ) { return -2; }

        if( c == 0 ) {
            obj->state |= STATE::DSSL_STATE_CONNECTED;
        return 1; }

    return -1; }

    /*─······································································─*/

    template< class T >
    int _read ( T* stream, char* bf, ulong sx ) const noexcept { return __read ( stream, bf, sx ); }
    
    template< class T >
    int _write( T* stream, char* bf, ulong sx ) const noexcept { return __write( stream, bf, sx ); }

    /*─······································································─*/

    template<class T>
    int __read( T* stream, char* bf, ulong sx ) const noexcept {
        if( !is_available() || stream->is_closed() ){ return -1; }
        
        int conn = _connect ( stream );
        if( conn<= 0 ){ return conn; }

        mbedtls_ssl_set_bio(&obj->ssl, (void*)stream, bio_write, bio_read, NULL);
        int c = mbedtls_ssl_read( &obj->ssl, (uchar*)bf, sx ); 
        
    return is_blocked(c); }

    template<class T>
    int __write( T* stream, char* bf, ulong sx ) const noexcept {
        if( !is_available() || stream->is_closed() ){ return -1; }
        
        int conn = _connect ( stream );
        if( conn<= 0 ){ return conn; }

        mbedtls_ssl_set_bio(&obj->ssl, (void*)stream, bio_write, bio_read, NULL);
        int c =  mbedtls_ssl_write( &obj->ssl, (const uchar*)bf, sx );
        
    return is_blocked(c); }
    
    /*─······································································─*/

    template< class T >
    int _write_( T* stream, char* bf, const ulong& sx, ulong* sy ) const noexcept {
    if( sx==0 || stream->is_closed() ){ return -1; } while( *sy<sx ) {
        int c = __write( stream, bf + *sy, sx - *sy );
        if( c==-2 ) /*--*/ { return -2; }
        if( c > 0 ){ *sy+= c; continue; } 
    break; } return *sy; }

    template< class T >
    int _read_( T* stream, char* bf, const ulong& sx, ulong* sy ) const noexcept {
    if( sx==0 || stream->is_closed() ){ return -1; } while( *sy<sx ) {
        int c = __read( stream, bf + *sy, sx - *sy );
        if( c==-2 ) /*--*/ { return -2; }
        if( c > 0 ){ *sy+= c; continue; } 
    break; } return *sy; }

    /*─······································································─*/

    void set_sni_callback ( onSNI callback ) const noexcept { 
         obj->sni = type::bind( callback ); 
    }

    /*─······································································─*/

    void free() { if( !is_available() ){ return; }
         mbedtls_ssl_close_notify( &obj->ssl );
         obj->state = STATE::DSSL_STATE_UNKNOWN;
    }

}; }

/*────────────────────────────────────────────────────────────────────────────*/

#endif

/*────────────────────────────────────────────────────────────────────────────*/