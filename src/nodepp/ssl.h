/*
 * Copyright 2023 The Nodepp Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/NodeppOfficial/nodepp/blob/main/LICENSE
 */

/*────────────────────────────────────────────────────────────────────────────*/

#ifndef NODEPP_SSL
#define NODEPP_SSL
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

/*────────────────────────────────────────────────────────────────────────────*/

#include "initializer.h"
#include "mbedtls/ssl.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp { class ssl_t {
protected:

    using onSNI = function_t<ssl_t*,string_t>;
    using onALP = function_t<bool  ,string_t>;

    enum STATE { 
         SSL_STATE_UNKNOWN   = 0b00000000,
         SSL_STATE_USED      = 0b00000010,
         SSL_STATE_CONNECTED = 0b00000001,
         SSL_STATE_SERVER    = 0b10000000
    };

    struct NODE {

        mbedtls_ssl_context      ssl;
        mbedtls_ssl_config       conf;
        mbedtls_x509_crt         cert;
        mbedtls_pk_context       pkey;
        mbedtls_entropy_context  entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        
        string_t key_path, crt_path, alpn;
        ptr_t<string_t> protocol_list;
        ptr_t<char*>    alpn_list;
        ptr_t<onSNI>    sni;

        int state = 0;

        NODE() {
            mbedtls_ssl_init       (&ssl) ;
            mbedtls_ssl_config_init(&conf);
            mbedtls_x509_crt_init  (&cert);
            mbedtls_pk_init        (&pkey);
            mbedtls_entropy_init   (&entropy);
            mbedtls_ctr_drbg_init  (&ctr_drbg);
        }

       ~NODE() {
            mbedtls_ssl_free       (&ssl) ;
            mbedtls_ssl_config_free(&conf);
            mbedtls_x509_crt_free  (&cert);
            mbedtls_pk_free        (&pkey);
            mbedtls_entropy_free   (&entropy);
            mbedtls_ctr_drbg_free  (&ctr_drbg);
        }

    };  ptr_t<NODE> obj;

    /*─······································································─*/
    
    bool is_connected() const noexcept { return obj->state & STATE::SSL_STATE_CONNECTED; }

    bool    is_server() const noexcept { return obj->state & STATE::SSL_STATE_SERVER; }

    bool is_available() const noexcept { return obj->state & STATE::SSL_STATE_USED; }

    /*─······································································─*/

    static int bio_send( void *ctx, const uchar *buf, size_t len ) {
    if( ctx==nullptr ){ return -1; }
        auto stream = (socket_t*)ctx;
    if( stream->is_closed() ){ return -1; }
        int  c = stream->socket_t::__write( (char*)buf, len ); 
    if( c==-2 ){ return MBEDTLS_ERR_SSL_WANT_WRITE; }
    return c; }

    static int bio_recv( void *ctx, uchar *buf, size_t len ) {
    if( ctx==nullptr ){ return -1; }
        auto stream = (socket_t*)ctx;
    if( stream->is_closed() ){ return -1; }
        int  c = stream->socket_t::__read( (char*)buf, len ); 
    if( c==-2 ){ return MBEDTLS_ERR_SSL_WANT_READ; }
    return c; }

    /*─······································································─*/

    static int sni_callback(void *arg, mbedtls_ssl_context *ssl, const uchar *name, size_t len) {

        if( name==nullptr || ssl==nullptr || arg==nullptr || len==0 ){ return 0; }
        
        onSNI func = *((onSNI*)arg); 

        string_t servername((char*)name, (ulong)len);
        ssl_t* new_ssl_obj = func( servername );
        
        if( new_ssl_obj != nullptr ){ 
            return mbedtls_ssl_set_hs_own_cert(
                   ssl, &new_ssl_obj->obj->cert, 
                   /**/ &new_ssl_obj->obj->pkey
        ); }

    return 0; }

    /*─······································································─*/

public:

    ssl_t() : obj( new NODE() ) {
        mbedtls_ctr_drbg_seed(&obj->ctr_drbg, mbedtls_entropy_func, &obj->entropy, NULL, 0);
        obj->state = STATE::SSL_STATE_USED;
    }

    ssl_t( const string_t& key, const string_t& cert ) : ssl_t() {
        obj->key_path = key; obj->crt_path = cert;
        obj->state = STATE::SSL_STATE_USED;
    }

    ssl_t( ssl_t& xtc, int /*unused*/ ) : obj( new NODE() ) { obj->state = xtc.obj->state;
        mbedtls_ctr_drbg_seed(&obj->ctr_drbg, mbedtls_entropy_func, &obj->entropy, NULL, 0);
        mbedtls_ssl_setup(&obj->ssl, &xtc.obj->conf);
        obj->alpn  = xtc.get_alpn_protocol();
        obj->state = STATE::SSL_STATE_USED;
    }

    /*─······································································─*/

    int create_server() { obj->state |= STATE::SSL_STATE_SERVER;

        mbedtls_ssl_config_defaults(&obj->conf, MBEDTLS_SSL_IS_SERVER, 
                                    MBEDTLS_SSL_TRANSPORT_STREAM, 
                                    MBEDTLS_SSL_PRESET_DEFAULT
        );
        
        if( !obj->crt_path.empty() )
          { mbedtls_x509_crt_parse_file(&obj->cert, obj->crt_path.get()); }
        if( !obj->key_path.empty() ){
            mbedtls_pk_parse_keyfile(&obj->pkey, obj->key_path.get(), NULL, 
                                     mbedtls_ctr_drbg_random, &obj->ctr_drbg);
        }

    //  mbedtls_ssl_conf_min_version(&obj->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
        mbedtls_ssl_conf_authmode   (&obj->conf, MBEDTLS_SSL_VERIFY_NONE);
        mbedtls_ssl_conf_ca_chain   (&obj->conf, obj->cert.next, NULL);
        mbedtls_ssl_conf_own_cert   (&obj->conf,&obj->cert,&obj->pkey);
        mbedtls_ssl_conf_rng        (&obj->conf, mbedtls_ctr_drbg_random, &obj->ctr_drbg);

        if( obj->sni != nullptr )
          { mbedtls_ssl_conf_sni(&obj->conf, sni_callback, obj->sni.get()); }

        if( !obj->alpn_list.null() )
          { mbedtls_ssl_conf_alpn_protocols( &obj->conf, (const char**)obj->alpn_list.get() ); }

    return 1; }

    /*─······································································─*/

    int create_client() { obj->state &=~ STATE::SSL_STATE_SERVER;

        mbedtls_ssl_config_defaults(&obj->conf, MBEDTLS_SSL_IS_CLIENT, 
                                    MBEDTLS_SSL_TRANSPORT_STREAM, 
                                    MBEDTLS_SSL_PRESET_DEFAULT
        );

    //  mbedtls_ssl_conf_min_version(&obj->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
        mbedtls_ssl_conf_rng        (&obj->conf, mbedtls_ctr_drbg_random, &obj->ctr_drbg);

        if( !obj->alpn_list.null() )
          { mbedtls_ssl_conf_alpn_protocols( &obj->conf, (const char**)obj->alpn_list.get() ); }

    return 1; }

    /*─······································································─*/

    void set_password( const char* /*pass*/ ) const noexcept {
    //  if( !is_available() ){ return; }
    //  SSL_CTX_set_default_passwd_cb( obj->ctx, &SNI_CLB );
    //  SSL_CTX_set_default_passwd_cb_userdata( obj->ctx, (void*)pass );
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

        mbedtls_ssl_set_bio( &obj->ssl, (void*)stream, bio_send, bio_recv, NULL );
        int c = mbedtls_ssl_handshake( &obj->ssl ); 
        
        if( c==MBEDTLS_ERR_SSL_WANT_WRITE ||
            c==MBEDTLS_ERR_SSL_WANT_READ
        ) { return -2; }

        if( c == 0 ) {
            obj->state |= STATE::SSL_STATE_CONNECTED;
            const char* alpn = mbedtls_ssl_get_alpn_protocol( &obj->ssl );
            obj->alpn = alpn ? alpn : "";
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
        while( _connect(stream)==-2 ){ process::next(); }
        if   ( !is_connected() )/*-*/{ return -1; }

        mbedtls_ssl_set_bio(&obj->ssl, (void*)stream, bio_send, bio_recv, NULL);
        int c = mbedtls_ssl_read( &obj->ssl,(uchar*)bf, sx ); 
        
        if( c==MBEDTLS_ERR_SSL_WANT_WRITE ||
            c==MBEDTLS_ERR_SSL_WANT_READ
        ) { return -2; }

    return c; }

    template<class T>
    int __write( T* stream, char* bf, ulong sx ) const noexcept {
        if( !is_available() || stream->is_closed() ){ return -1; }
        while( _connect(stream)==-2 ){ process::next(); }
        if   ( !is_connected() )/*-*/{ return -1; }

        mbedtls_ssl_set_bio(&obj->ssl, (void*)stream, bio_send, bio_recv, NULL);
        int c =  mbedtls_ssl_write( &obj->ssl, (const uchar*)bf, sx );
        
        if( c==MBEDTLS_ERR_SSL_WANT_WRITE ||
            c==MBEDTLS_ERR_SSL_WANT_READ
        ) { return -2; }
    
    return c; }

    /*─······································································─*/

    template< class T >
    int _write_( T* stream, char* bf, const ulong& sx, ulong* sy ) const noexcept {
        if( sx==0 || stream->is_closed() ){ return -1; } while( *sy<sx ) {
            int c = __write( stream, bf + *sy, sx - *sy );
            if( c <= 0 && c != -2 ) /*----*/ { return -2; }
            if( c >  0 ){ *sy+= c; continue; } break/**/;
        }   return sx;
    }

    template< class T >
    int _read_( T* stream, char* bf, const ulong& sx, ulong* sy ) const noexcept {
        if( sx==0 || stream->is_closed() ){ return -1; } while( *sy<sx ) {
            int c = __read( stream, bf + *sy, sx - *sy );
            if( c <= 0 && c != -2 ) /*----*/ { return -2; }
            if( c >  0 ){ *sy+= c; continue; } break/**/;
        }   return sx;
    }

    /*─······································································─*/

    void set_sni_callback ( onSNI  callback ) const noexcept { 
         obj->sni = type::bind( callback ); 
    }

    string_t get_alpn_protocol() const noexcept { return obj->alpn; }

    /*─······································································─*/

    int set_alpn_protocol_list( const initializer_t<string_t>& protocol_list ) const noexcept { 
    if( protocol_list.empty() ){ return -1; }
        obj->protocol_list = protocol_list;

        obj->alpn_list.resize( protocol_list.size()+1 );
        obj->alpn_list.fill  ( nullptr );

        for( int x=protocol_list.size(); x-->0; ){ 
             obj->alpn_list[x] = protocol_list[x].get(); 
        }

    return  1; }

    /*─······································································─*/

    void free() { if( !is_available() ){ return; }
         mbedtls_ssl_close_notify( &obj->ssl );
         obj->state = STATE::SSL_STATE_UNKNOWN;
    }

}; }

/*────────────────────────────────────────────────────────────────────────────*/

#endif

/*────────────────────────────────────────────────────────────────────────────*/