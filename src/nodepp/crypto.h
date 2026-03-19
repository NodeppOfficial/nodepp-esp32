/*
 * Copyright 2023 The Nodepp Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/NodeppOfficial/nodepp/blob/main/LICENSE
 */

/*────────────────────────────────────────────────────────────────────────────*/

#ifndef NODEPP_CRYPTO
#define NODEPP_CRYPTO
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#define CRYPTO_BASE64 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

/*────────────────────────────────────────────────────────────────────────────*/

#include "encoder.h"
#include "fs.h"

/*────────────────────────────────────────────────────────────────────────────*/

#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/ecp.h>
#include <mbedtls/x509.h>
#include <mbedtls/error.h>
#include <mbedtls/cipher.h>
#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp {

class hash_t {
protected:

    struct NODE {
        mbedtls_md_context_t ctx;
        ptr_t<uchar> bff;

        uint length = 0;
        bool  state = 0;

        NODE() { mbedtls_md_init(&ctx); }
       ~NODE() { mbedtls_md_free(&ctx); }
    };  ptr_t<NODE> obj;

    string_t hex() const noexcept { free(); 
        return { (char*)obj->bff.data(), obj->length }; 
    }

public:

    hash_t( mbedtls_md_type_t type, ulong output_length ) : obj( new NODE() ) { 
        
        obj->bff    = ptr_t<uchar>( output_length );
        obj->length = output_length;
        
        const mbedtls_md_info_t* info = mbedtls_md_info_from_type(type);
        
        if ( info == NULL || 
             mbedtls_md_setup ( &obj->ctx, info, 0 ) != 0 || 
             mbedtls_md_starts( &obj->ctx )          != 0 
        )  { ARDUINO_ERROR("can't initialize mbedtls hash_t"); }
        
        obj->state = 1;
    }

   ~hash_t() noexcept { 
        if( obj.count() > 1 ){ return; } free(); 
    }

    void update( string_t msg ) const noexcept { 
        if( !obj->state ){ return; } 
        mbedtls_md_update( &obj->ctx, (const uchar*)msg.data(), msg.size() );
    }

    void free() const noexcept { 
        if( obj->state == 0 ){ return; } obj->state = 0;
        mbedtls_md_finish( &obj->ctx, (uchar*)obj->bff.data() );
    }

    bool is_available() const noexcept { return obj->state == 1; }
    bool is_closed   () const noexcept { return obj->state == 0; }

    string_t get() const noexcept { 
        return encoder::buffer::buff2hex( this->hex() );
    }

    void close() const noexcept { free(); } 

};

/*────────────────────────────────────────────────────────────────────────────*/

class hmac_t {
protected:

    struct NODE {
        mbedtls_md_context_t ctx;
        ptr_t<uchar> bff; 

        uint length = 0;
        bool  state = 0;

        NODE() { mbedtls_md_init(&ctx); }
       ~NODE() { mbedtls_md_free(&ctx); }
    };  ptr_t<NODE> obj;

    string_t hex() const noexcept { free(); 
        return { (char*)obj->bff.data(), obj->length }; 
    }

public:

    template< class T >
    hmac_t( const string_t& key, const T& type, ulong length ) : obj( new NODE() ) { 
        if( key.empty() ){ ARDUINO_ERROR("can't initializate hmac_t"); }

        obj->bff    = ptr_t<uchar>( length ); 
        obj->length = (uint)length;
        
        const mbedtls_md_info_t* info = mbedtls_md_info_from_type(type);

        if ( info == nullptr ||  mbedtls_md_setup( &obj->ctx, info, 1 )                != 0 || 
             mbedtls_md_hmac_starts( &obj->ctx, (const uchar*)key.data(), key.size() ) != 0 
        )  { ARDUINO_ERROR("can't initialize mbedtls hmac_t"); }

        obj->state = 1;
    }
    
   ~hmac_t() noexcept { if( obj.count() > 1 ){ return; } free(); }

    mbedtls_md_context_t* get_fd() const noexcept { return &obj->ctx; }

    void update( string_t msg ) const noexcept { 
        if( !obj->state ){ return; }
        mbedtls_md_hmac_update( &obj->ctx, (const uchar*)msg.data(), msg.size() );
    }

    void free() const noexcept {
        if( obj->state == 0 ){ return; } obj->state = 0;
        mbedtls_md_hmac_finish( &obj->ctx, (uchar*)obj->bff.data() ); 
    }

    string_t get() const noexcept { return encoder::buffer::buff2hex( this->hex() ); }

    bool is_available() const noexcept { return obj->state == 1; }
    bool    is_closed() const noexcept { return obj->state == 0; }
    void        close() const noexcept { free(); } 

};

/*────────────────────────────────────────────────────────────────────────────*/

class xor_t {
protected:

    struct CTX {
        string_t key;
        ulong    pos;
    };

    struct NODE {
        ptr_t<CTX>  ctx;
        string_t    bff;
        bool    state=0;
    };  ptr_t<NODE> obj;

public:

    event_t<>         onClose;
    event_t<string_t> onData;

    xor_t( const string_t& key ) : obj( new NODE() ) {
        if( key.empty() ){ ARDUINO_ERROR("can't initializate xor_t"); }

        CTX item1; //memset( &item1, 0, sizeof(CTX) );
            item1.key  = key; item1.pos = 0;
            obj->state = 1;

        obj->ctx = ptr_t<CTX> ({ item1 });
    }

    xor_t() noexcept : obj( new NODE() ) { obj->state = 0; }
    
   ~xor_t() noexcept { if( obj.count()>1 ){ return; } free(); }

    void update( string_t msg ) const noexcept { 
        if( !obj->state ){ return; } ulong chunk=0, /*-------------*/ base=CHUNK_SIZE;
        while( chunk < msg.size() ){ string_t tmp = msg.slice_view( chunk, chunk + base );
            forEach( y, obj->ctx ){ forEach( x, tmp ){ 
                x = x ^ y.key[ y.pos % y.key.size() ]; ++y.pos; 
            }} if ( tmp.empty() )     { return; }
             elif ( onData.empty() )  { obj->bff +=tmp; }
             else { onData.emit(tmp); }
        chunk += base; }
    }

    bool is_available() const noexcept { return obj->state == 1; }

    bool is_closed() const noexcept { return obj->state == 0; }

    string_t get() const noexcept { free(); return obj->bff; }

    void free() const noexcept { 
        if ( obj->state == 0 ){ return; } 
             obj->state = 0; onClose.emit(); 
             onData.clear();
    }

    void close() const noexcept { free(); } 

};

/*────────────────────────────────────────────────────────────────────────────*/

class encrypt_t {
protected:
    struct NODE {
        ptr_t<uchar> bff; string_t buff;
        mbedtls_cipher_context_t ctx;

        bool     state = 0;
        size_t out_len = 0;

        NODE() { mbedtls_cipher_init(&ctx); }
       ~NODE() { mbedtls_cipher_free(&ctx); }
    };  ptr_t<NODE> obj;

    void _init_( mbedtls_cipher_type_t type, const string_t& key, const string_t& iv ) {
        if( key.empty() ){ ARDUINO_ERROR("can't initializate encrypt_t"); }

        const mbedtls_cipher_info_t* info = mbedtls_cipher_info_from_type(type);
        if( !info ){ ARDUINO_ERROR("Unsupported cipher type"); }

        uint ky_size = mbedtls_cipher_info_get_key_bitlen(info) / 8;
        uint iv_size = MBEDTLS_MAX_IV_LENGTH;
        obj->bff     = ptr_t<uchar>(CHUNK_SIZE,'\0');
        obj->state   = 1;

        ptr_t<uchar> nkey( (ulong)ky_size, 0x00 );
        ptr_t<uchar> niv ( (ulong)iv_size, 0x00 );
        memcpy( nkey.get(), key.get(), min( nkey.size(), key.size() ) );
        memcpy( niv .get(), iv .get(), min( niv .size(), iv .size() ) );

        if( mbedtls_cipher_setup(&obj->ctx, info)!=0 )
          { ARDUINO_ERROR("mbedtls _init_ failed"); }

        if( mbedtls_cipher_setkey(&obj->ctx, nkey.get(), nkey.size() * 8, MBEDTLS_ENCRYPT )!=0 ) 
          { ARDUINO_ERROR("mbedtls encrypt setkey failed"); }
        
        if( mbedtls_cipher_set_iv(&obj->ctx, niv.get(), mbedtls_cipher_get_iv_size(&obj->ctx))!=0 )
          { ARDUINO_ERROR("mbedtls set_iv failed"); }

        mbedtls_cipher_reset(&obj->ctx); 
    //  mbedtls_cipher_set_padding_mode(&obj->ctx, MBEDTLS_PADDING_PKCS7);

    }

public:
    event_t<string_t> onData;
    event_t<>         onClose;

    encrypt_t( const string_t& iv, const string_t& key, mbedtls_cipher_type_t type ) : obj( new NODE() ) { 
        _init_(type, key, iv);
    }

    encrypt_t( const string_t& key, mbedtls_cipher_type_t type ) : obj( new NODE() ) { 
        _init_(type, key, nullptr); 
    }

   ~encrypt_t() noexcept { if( obj.count() > 1 ){ return; } free(); }

    mbedtls_cipher_context_t* get_fd() const noexcept { return &obj->ctx; }

    void update( string_t msg ) const noexcept { 
        if( !obj->state ){ return; }
        if( mbedtls_cipher_update(&obj->ctx, (const uchar*)msg.data(), msg.size(), 
                                  obj->bff.get(), &obj->out_len) == 0
        ) { if( obj->out_len>0 ) {
            string_t chunk((char*)obj->bff.get(), (ulong)obj->out_len);
        if( onData.empty() ) {
                 obj->buff += chunk;
        } else { onData.emit(chunk); }} }
    }

    void free() const noexcept { 
        if( obj->state == 0 ){ return; } obj->state = 0;

        if( mbedtls_cipher_finish(&obj->ctx, obj->bff.get(), &obj->out_len)==0 )
          { if( obj->out_len>0 ) {
            string_t chunk((char*)obj->bff.get(), (ulong)obj->out_len);
        if( onData.empty() ) {
                 obj->buff += chunk;
        } else { onData.emit(chunk); }} }

        onClose.emit(); onData.clear();
    }

    bool is_available() const noexcept { return obj->state == 1; }
    string_t      get() const noexcept { free(); return obj->buff; }
    bool    is_closed() const noexcept { return obj->state == 0; }
    void        close() const noexcept { free(); } 

};

/*────────────────────────────────────────────────────────────────────────────*/

class decrypt_t {
protected:

    struct NODE {
        ptr_t<uchar> bff; string_t buff;
        mbedtls_cipher_context_t ctx;

        bool     state = 0;
        size_t out_len = 0; 

        NODE() { mbedtls_cipher_init(&ctx); }
       ~NODE() { mbedtls_cipher_free(&ctx); }
    };  ptr_t<NODE> obj;

    void _init_(mbedtls_cipher_type_t type, const string_t& key, const string_t& iv) {
        if( key.empty() ){ ARDUINO_ERROR("can't initializate decrypt_t"); }

        const mbedtls_cipher_info_t* info = mbedtls_cipher_info_from_type(type);
        if( !info ){ ARDUINO_ERROR("Unsupported cipher type"); }

        uint ky_size = mbedtls_cipher_info_get_key_bitlen(info) / 8;
        uint iv_size = MBEDTLS_MAX_IV_LENGTH;
        obj->bff     = ptr_t<uchar>(CHUNK_SIZE,'\0');
        obj->state   = 1;

        ptr_t<uchar> nkey( (ulong)ky_size, 0x00 );
        ptr_t<uchar> niv ( (ulong)iv_size, 0x00 );
        memcpy( nkey.get(), key.get(), min( nkey.size(), key.size() ) );
        memcpy( niv .get(), iv .get(), min( niv .size(), iv .size() ) );

        if( mbedtls_cipher_setup(&obj->ctx, info)!=0 )
          { ARDUINO_ERROR("mbedtls _init_ failed"); }

        if( mbedtls_cipher_setkey(&obj->ctx, nkey.get(), nkey.size() * 8, MBEDTLS_DECRYPT )!=0 ) 
          { ARDUINO_ERROR("mbedtls decrypt setkey failed"); }
        
        if( mbedtls_cipher_set_iv(&obj->ctx, niv.get(), mbedtls_cipher_get_iv_size(&obj->ctx))!=0 )
          { ARDUINO_ERROR("mbedtls set_iv failed"); }
        
        mbedtls_cipher_reset(&obj->ctx); 
    //  mbedtls_cipher_set_padding_mode(&obj->ctx, MBEDTLS_PADDING_PKCS7);
    }

public:
    event_t<string_t> onData;
    event_t<>         onClose;

    template< class T >
    decrypt_t( const string_t& key, const T& type ) : obj( new NODE() ) { 
        _init_(type, key, nullptr); 
    }

    template< class T >
    decrypt_t( const string_t& iv, const string_t& key, const T& type ) : obj( new NODE() ) { 
        _init_(type, key, iv);
    }

   ~decrypt_t() noexcept { if( obj.count() > 1 ){ return; } free(); }

    void update( string_t msg ) const noexcept { 
        if( !obj->state ){ return; }
        if( mbedtls_cipher_update(&obj->ctx, (const uchar*)msg.data(), msg.size(), 
                                  obj->bff.get(), &obj->out_len) == 0
        ) { if( obj->out_len>0 ) {
            string_t chunk((char*)obj->bff.get(), (ulong)obj->out_len);
        if( onData.empty() ) {
                 obj->buff += chunk;
        } else { onData.emit(chunk); }}}
    }

    void free() const noexcept { 
        if( obj->state == 0 ){ return; } obj->state = 0;

        if( mbedtls_cipher_finish(&obj->ctx, obj->bff.get(), &obj->out_len)==0 )
          { if( obj->out_len>0 ) {
            string_t chunk((char*)obj->bff.get(), (ulong)obj->out_len);
        if( onData.empty() ) {
                 obj->buff += chunk;
        } else { onData.emit(chunk); }}}
        
        onClose.emit(); onData.clear();
    }

    bool is_available() const noexcept { return obj->state == 1; }
    string_t      get() const noexcept { free(); return obj->buff; }
    bool    is_closed() const noexcept { return obj->state == 0; }
    void        close() const noexcept { free(); } 

};

/*────────────────────────────────────────────────────────────────────────────*/

class encoder_t {
protected:
    struct NODE {
        
        bool state=0; mbedtls_mpi bn; 
        queue_t<string_t> bff;
        string_t chr; 

        NODE() { mbedtls_mpi_init(&bn); }
       ~NODE() { mbedtls_mpi_free(&bn); }
    }; 
    ptr_t<NODE> obj;

    string_t encode(string_t msg) const noexcept {
        if( msg.empty() ){ return ""; }

        mbedtls_mpi_lset(&obj->bn, 0); string_t result;
        mbedtls_mpi_uint base = (mbedtls_mpi_uint)obj->chr.size();
        mbedtls_mpi_read_binary(&obj->bn, (const unsigned char*)msg.data(), msg.size());

        while( mbedtls_mpi_cmp_int(&obj->bn, 0)>0 ) { mbedtls_mpi_uint r_val;
           if( mbedtls_mpi_mod_int(&r_val, &obj->bn, base) /*------*/ !=0 ) break;
           if( mbedtls_mpi_div_int(&obj->bn, nullptr, &obj->bn, base) !=0 ) break;

            result.unshift(obj->chr[(size_t)r_val]);
        }

        for( size_t i = 0; i<msg.size() && (unsigned char)msg[i]==0; i++ ) 
           { result.unshift(obj->chr[0]); }

        if (!onData.empty()){ onData.emit(result); }
        return result;
    }

public:
    event_t<string_t> onData;
    event_t<>         onClose;

    encoder_t(const string_t& chr) : obj(0UL, NODE()) { 
        obj->state = 1; obj->chr = chr;
    }
    
   ~encoder_t() noexcept { if( obj.count()>1 ){ return; } free(); }

    string_t get() const noexcept { 
        if (obj->state == 0) return nullptr;
        auto raw = array_t<string_t>(obj->bff.data()).join(nullptr);
        auto data = encode(raw); 
        free(); 
        return data; 
    }

    void update(const string_t& msg) const noexcept { 
        if(!obj->state) return; 
        obj->bff.push(msg);
    }

    void free() const noexcept { 
        if( obj->state==0 ){return; } obj->state = 0;
        onClose.emit(); onData.clear();
    }

    bool is_available() const noexcept { return obj->state == 1; }
    bool is_closed() const noexcept { return obj->state == 0; }
    void close() const noexcept { free(); }

};

/*────────────────────────────────────────────────────────────────────────────*/

class decoder_t {
protected:
    struct NODE {
        string_t chr; 
        bool state = 0;
        queue_t<string_t> bff;
        mbedtls_mpi bn;

        NODE() { mbedtls_mpi_init(&bn); }
        ~NODE() { mbedtls_mpi_free(&bn); }
    }; 
    ptr_t<NODE> obj;

    string_t decode(string_t msg) const noexcept {
        if (msg.empty()) return nullptr;

        mbedtls_mpi_lset(&obj->bn, 0);
        
        size_t lz   = 0; bool ch = true;
        size_t base = obj->chr.size();

        for(const auto& c : msg) {
        if (ch && c == obj->chr[0]){ lz++; } else { ch = false; }

            const char* pos = strchr(obj->chr.data(), c);
            if( pos == nullptr ){ return nullptr; }
            
            size_t val = pos - obj->chr.data();

            mbedtls_mpi_mul_int(&obj->bn, &obj->bn, base);
            mbedtls_mpi_add_int(&obj->bn, &obj->bn, val);
        }

        size_t num_bytes = mbedtls_mpi_size(&obj->bn); 
        ptr_t<uchar> tmp(lz + num_bytes, '\0');
        
        if( num_bytes > 0 ) 
          { mbedtls_mpi_write_binary(&obj->bn, tmp.data() + lz, num_bytes); }

        string_t out((char*)tmp.data(), tmp.size());
        if( !onData.empty() ) { onData.emit(out); }

        return out; 
    }

public:
    event_t<string_t> onData;
    event_t<>         onClose;

    decoder_t(const string_t& chr) : obj(0UL, NODE()) { 
        obj->state = 1; obj->chr = chr;
    }
    
   ~decoder_t() noexcept { if( obj.count()>1 ){ return; } free(); }

    void update(const string_t& msg) const noexcept { 
        if(!obj->state){ return; } obj->bff.push(msg);
    }

    string_t get() const noexcept { 
        if( obj->state==0 ){ return nullptr; }
        auto raw  = array_t<string_t>(obj->bff.data()).join(nullptr);
        auto data = decode(raw); 
        free(); return data; 
    }

    void free() const noexcept { 
        if( obj->state==0 ){ return; } obj->state = 0;
        onClose.emit(); onData.clear();
    }

    bool is_available() const noexcept { return obj->state == 1; }
    bool is_closed() const noexcept { return obj->state == 0; }
    void close() const noexcept { free(); } 

};

/*────────────────────────────────────────────────────────────────────────────*/

class base64_encoder_t {
protected:

    struct CTX {
        int pos1, pos2;
        ulong     size;
        ulong     len;
    };

    struct NODE {
        queue_t<string_t> buff;
        ptr_t<char> bff;
        ptr_t<CTX>  ctx;
        bool    state=0;
    };  ptr_t<NODE> obj;

public:

    event_t<>         onClose;
    event_t<string_t> onData;

   ~base64_encoder_t() noexcept { if( obj.count()>1 ){ return; } free(); }

    base64_encoder_t() noexcept : obj( new NODE() ) {
        obj->state = 1; obj->bff = ptr_t<char>( CHUNK_SIZE, '\0' );

        CTX item1; memset( &item1, 0, sizeof(CTX) );
            item1.pos1 = 0; item1.pos2 =-6; 
            item1.size = 0; item1.len  = 0;

        obj->ctx = type::bind( item1 );
    }

    void update( string_t msg ) const noexcept { 
        if( !obj->state ){ return; } ulong chunk=0, /*--------*/ base=obj->bff.size();
        while( chunk < msg.size() ){ string_t tmp = msg.slice_view( chunk, chunk + base );
            string_t out; obj->ctx->len = 0; forEach ( x, tmp ) {

                obj->ctx->pos1 = ( obj->ctx->pos1 << 8 ) + x; obj->ctx->pos2 += 8;

                while ( obj->ctx->pos2 >= 0 ) { 
                    obj->bff[obj->ctx->len] = CRYPTO_BASE64[(obj->ctx->pos1>>obj->ctx->pos2)&0x3F];
                    obj->ctx->pos2 -= 6; ++obj->ctx->len;
                }

            }   obj->ctx->size += obj->ctx->len; out = string_t( &obj->bff, obj->ctx->len );

            if ( obj->ctx->len == 0 ){ return; }
            if ( onData.empty()     ){ obj->buff.push( out ); } else { onData.emit( out ); }
        chunk += base; }
    }

    void free() const noexcept { if ( obj->state == 0 ){ return; } 
        string_t out; obj->state = 0; obj->ctx->len = 0;

        if( obj->ctx->pos2 > -6 ){ 
            obj->bff[obj->ctx->len] = CRYPTO_BASE64[((obj->ctx->pos1<<8)>>(obj->ctx->pos2+8))&0x3F];
            obj->ctx->len++; 
        } while ( ( obj->ctx->len + obj->ctx->size ) % 4 ){ 
            obj->bff[obj->ctx->len] = '='; 
            obj->ctx->len++;
        } 

        obj->ctx->size += obj->ctx->len; out = string_t( &obj->bff, obj->ctx->len );
        if ( onData.empty() ) { obj->buff.push( out ); } else { onData.emit(out); }
             onClose.emit(); onData.clear();
    }

    string_t get() const noexcept { free(); return array_t<string_t>( obj->buff.data() ).join(nullptr); }

    bool is_available() const noexcept { return obj->state == 1; }

    bool is_closed() const noexcept { return obj->state == 0; }

    void close() const noexcept { free(); } 

};

/*────────────────────────────────────────────────────────────────────────────*/

class base64_decoder_t {
protected:

    struct CTX {
        int pos1, pos2;
        ulong     size;
        ulong      len;
        int    T [255];
    };

    struct NODE {
        queue_t<string_t> buff;
        ptr_t<char> bff;
        ptr_t<CTX>  ctx;
        bool    state=0;
    };  ptr_t<NODE> obj;

public:

    event_t<>         onClose;
    event_t<string_t> onData;

   ~base64_decoder_t() noexcept { if( obj.count()>1 ){ return; } free(); }

    base64_decoder_t() noexcept : obj( new NODE() ) {
        obj->state = 1; obj->bff = ptr_t<char>( CHUNK_SIZE, '\0' );

        CTX item1; memset( &item1, 0, sizeof(CTX) );
            item1.pos1 = 0; item1.pos2 =-8; 
            item1.size = 0; item1.len  = 0;

        obj->ctx = type::bind( item1 );
    }

    void update( string_t msg ) const noexcept { 
        if( !obj->state ){ return; } ulong chunk=0, /*--------*/ base=obj->bff.size();
        while( chunk < msg.size() ){ string_t tmp = msg.slice_view( chunk, chunk + base );
        for  ( int x=0; x<64; x++ ){ obj->ctx->T[type::cast<int>(CRYPTO_BASE64[x])] =x; }

            string_t out; obj->ctx->len = 0; forEach ( x, tmp ) {
                uint   y = type::cast<uint>(x);

                if( obj->ctx->T[y]==-1 ){ break; }

                obj->ctx->pos1 = ( obj->ctx->pos1 << 6 ) + obj->ctx->T[y]; obj->ctx->pos2 += 6;

                if( obj->ctx->pos2 >= 0 ) {
                    obj->bff[obj->ctx->len] = char((obj->ctx->pos1>>obj->ctx->pos2)&0xFF);
                    obj->ctx->pos2 -= 8; ++obj->ctx->len;
                }

            }   obj->ctx->size += obj->ctx->len; out = string_t( &obj->bff, obj->ctx->len );

            if ( obj->ctx->len == 0 ){ return; }
            if ( onData.empty()     ){ obj->buff.push(out); } else { onData.emit( out ); }
        chunk += base; }
    }

    void free() const noexcept { 
    if( obj->state == 0 ){ return; } 
        obj->state =  0; onClose.emit(); onData.clear();
    }

    string_t get() const noexcept { free(); return array_t<string_t>( obj->buff.data() ).join(nullptr); }

    bool is_available() const noexcept { return obj->state == 1; }

    bool is_closed() const noexcept { return obj->state == 0; }

    void close() const noexcept { free(); } 

};

/*────────────────────────────────────────────────────────────────────────────*/

class rsa_t {
protected:

    static int PASS_CLB( void *data, size_t max_len, size_t *olen, void *p_ctx ) {
        if( p_ctx == nullptr ){ return -1; }
        const char* pass = (const char*)p_ctx;
        size_t len = strlen(pass);
        if( len > max_len ){ return -1; }
        memcpy(data, pass, len);
        *olen = len;
        return 0;
    }

    struct NODE {

        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_context entropy;
        mbedtls_pk_context pk;
        ptr_t<uchar> bff;
        bool state = 0;

        NODE() {
            mbedtls_pk_init(&pk);
            mbedtls_entropy_init(&entropy);
            mbedtls_ctr_drbg_init(&ctr_drbg);
        }

       ~NODE() {
            mbedtls_pk_free(&pk);
            mbedtls_entropy_free(&entropy);
            mbedtls_ctr_drbg_free(&ctr_drbg);
        }

    };  ptr_t<NODE> obj;

public:

    rsa_t() : obj(0UL, NODE()) {
        if( mbedtls_ctr_drbg_seed(&obj->ctr_drbg, mbedtls_entropy_func, &obj->entropy, 
                                  (const uchar*)"rsa_t", 5)  !=0
        ) { ARDUINO_ERROR("failed to seed RNG"); } obj->state=1;
    }

   ~rsa_t() noexcept { if (obj.count() > 1) return; free(); }

    int generate_keys(uint len = 2048) const noexcept {
        len = clamp(len, 1024u, 4096u);
        if( mbedtls_pk_setup(&obj->pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0) return -1;
        
        int res = mbedtls_rsa_gen_key( mbedtls_pk_rsa(obj->pk), mbedtls_ctr_drbg_random, 
                                      &obj->ctr_drbg, len, 65537 );
        if( res == 0 ) obj->bff.resize(mbedtls_pk_get_len(&obj->pk));
        return res;
    }

    void read_private_key_from_memory( const string_t& key, const char* pass = NULL ) const {
        int res = mbedtls_pk_parse_key(&obj->pk, (const uchar*)key.data(), key.size() + 1, 
                                       (const uchar*)pass, pass ? strlen(pass) : 0,
                                       mbedtls_ctr_drbg_random, &obj->ctr_drbg );
        if( res != 0 ){ ARDUINO_ERROR("Invalid RSA Private Key"); }
        obj->bff.resize(mbedtls_pk_get_len(&obj->pk));
    }

    void read_public_key_from_memory( const string_t& key, const char* pass = NULL ) const {
        int res = mbedtls_pk_parse_public_key(&obj->pk, (const uchar*)key.data(), key.size() + 1);
        if( res != 0 ){ ARDUINO_ERROR("Invalid RSA Public Key"); }
        obj->bff.resize(mbedtls_pk_get_len(&obj->pk));
    }

    string_t write_private_key_to_memory( const char* pass = NULL ) const { 
        ptr_t<char> out ( 16000UL, 0x00 ); 
        if( mbedtls_pk_write_key_pem( &obj->pk, (uchar*)out.get(), out.size() ) !=0 )
          { ARDUINO_ERROR("Failed to write private key to PEM"); } return out;
    }

    string_t write_public_key_to_memory( const char* pass = NULL ) const {
        ptr_t<char> out ( 8000UL, 0x00 ); 
        if( mbedtls_pk_write_pubkey_pem( &obj->pk, (uchar*)out.get(), out.size() ) !=0 )
          { ARDUINO_ERROR("Failed to write public key to PEM"); } return out;
    }

    int read_private_key( const string_t& path, const char* pass=NULL ) const {
        auto raw = fs::read_file( "path" ).await(); if( !raw ){ return -1; }
        read_private_key_from_memory( raw.value(), pass ); return 1; 
    }

    int read_public_key( const string_t& path, const char* pass=NULL ) const {
        auto raw = fs::read_file( "path" ).await(); if( !raw ){ return -1; }
        read_public_key_from_memory( raw.value(), pass ); return 1; 
    }

    int write_private_key( const string_t& path, const char* pass=NULL ) const {
        auto raw = fs::write_file( "path", write_private_key_to_memory( pass ) ).await(); 
        if( !raw ){ return -1; } return 1;
    }

    int write_public_key( const string_t& path, const char* pass=NULL ) const {
        auto raw = fs::write_file( "path", write_public_key_to_memory( pass ) ).await();
        if( !raw ){ return -1; } return 1;
    }

    string_t public_encrypt( string_t msg ) const {
        if( msg.empty() || !obj->state ){ return nullptr; }

        ulong chunk_size = mbedtls_pk_get_len(&obj->pk) - 11;
        string_t data; size_t out_len;

        while( !msg.empty() ) {
            string_t tmp = msg.splice(0, chunk_size);

            if( mbedtls_pk_encrypt(&obj->pk, (const uchar*)tmp.data(), tmp.size(),
                                    obj->bff.get(), &out_len, obj->bff.size(),
                                    mbedtls_ctr_drbg_random, &obj->ctr_drbg) != 0
            ){ return nullptr; }
            
            data += string_t((char*)obj->bff.get(), (ulong)out_len);
        }

        return data;
    }

    string_t private_decrypt(string_t msg) const {
        if( msg.empty() || !obj->state ){ return nullptr; }
        
        ulong block_size = mbedtls_pk_get_len(&obj->pk);
        string_t data; size_t out_len;

        while( !msg.empty() ) {
            string_t tmp = msg.splice(0, block_size);
        if( mbedtls_pk_decrypt(&obj->pk, (const uchar*)tmp.data(), tmp.size(),
                                obj->bff.get(), &out_len, obj->bff.size(),
                                mbedtls_ctr_drbg_random, &obj->ctr_drbg) != 0
        ) { return nullptr; } data += string_t((char*)obj->bff.get(), (ulong)out_len); }

        return data;
    }

    void free() const noexcept { if( obj->state == 0 ){ return; } obj->state = 0; }

};

/*────────────────────────────────────────────────────────────────────────────*/


class ec_t {
protected:

    struct NODE {

        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_context entropy;
        mbedtls_ecp_keypair keypair;

        bool state = 0;

        NODE() {
            mbedtls_ecp_keypair_init(&keypair);
            mbedtls_ctr_drbg_init(&ctr_drbg);
            mbedtls_entropy_init(&entropy);
            mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
        }

        ~NODE() {
            mbedtls_ecp_keypair_free(&keypair);
            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);
        }

    }; ptr_t<NODE> obj;

public:

    template< class T >
    ec_t( const string_t& key, const T& type ) noexcept : obj( new NODE() ) {
        if( key.empty() ){ ARDUINO_ERROR("can't initializate ec_t"); }

        if( mbedtls_ecp_group_load(&obj->keypair.grp, type) != 0 ) /*---*/ { return; }
        if( mbedtls_mpi_read_string(&obj->keypair.d, 16, key.data()) != 0 ){ return; }

        if( mbedtls_ecp_mul(&obj->keypair.grp, &obj->keypair.Q, 
                            &obj->keypair.d, &obj->keypair.grp.G, 
                            mbedtls_ctr_drbg_random, &obj->ctr_drbg) != 0 ){ return; }

        obj->state = 1;
    }

    template< class T >
    ec_t( const T& type ) noexcept : obj( new NODE() ) {
        if( mbedtls_ecp_group_load(&obj->keypair.grp, type) != 0 ){ return; }

        if( mbedtls_ecp_gen_keypair(&obj->keypair.grp, &obj->keypair.d, 
                                    &obj->keypair.Q, mbedtls_ctr_drbg_random, 
                                    &obj->ctr_drbg) != 0 ) { return; }
        
        obj->state = 1;
    }

   ~ec_t() noexcept { if( obj.count() > 1 ) return; free(); }

    string_t get_public_key( uint x = 0 ) const noexcept {
        if( !obj->state ){ return nullptr; }
        
        uchar buffer[300]; size_t len = 0;
        
        int format = (x == 1) ? MBEDTLS_ECP_PF_COMPRESSED : MBEDTLS_ECP_PF_UNCOMPRESSED;

        if( mbedtls_ecp_point_write_binary(&obj->keypair.grp, &obj->keypair.Q, 
                                           format, &len, buffer, sizeof(buffer)) != 0 
        ) { return nullptr; }
        
        return encoder::buffer::buff2hex({ (char*)buffer, (ulong)len });
    }

    string_t get_private_key() const noexcept {
        if( !obj->state ){ return nullptr; } char buffer[256]; size_t len = 0;
        mbedtls_mpi_write_string(&obj->keypair.d, 16, buffer, sizeof(buffer), &len);
        return string_t(buffer);
    }

    void free() const noexcept {
         if( obj->state == 0 ){ return; } obj->state = 0;
    }

    bool is_available() const noexcept { return obj->state == 1; }
    bool is_closed()    const noexcept { return obj->state == 0; }
    void close()        const noexcept { free(); }

};

/*────────────────────────────────────────────────────────────────────────────*/

namespace crypto { namespace hash {

    class MD5 : public hash_t { public:
        MD5() : hash_t( MBEDTLS_MD_MD5, 16 ) {}
    };

    class SHA1 : public hash_t { public:
        SHA1() : hash_t( MBEDTLS_MD_SHA1, 20 ) {}
    };

    class SHA256 : public hash_t { public:
        SHA256() : hash_t( MBEDTLS_MD_SHA256, 32 ) {}
    };

    class SHA384 : public hash_t { public:
        SHA384() : hash_t( MBEDTLS_MD_SHA384, 48 ) {}
    };

    class SHA512 : public hash_t { public:
        SHA512() : hash_t( MBEDTLS_MD_SHA512, 64 ) {}
    };

    class SHA3_256 : public hash_t { public:
        SHA3_256() : hash_t( MBEDTLS_MD_SHA3_256, 32 ) {}
    };

    class SHA3_384 : public hash_t { public:
        SHA3_384() : hash_t( MBEDTLS_MD_SHA3_384, 48 ) {}
    };

    class SHA3_512 : public hash_t { public:
        SHA3_512() : hash_t( MBEDTLS_MD_SHA3_512, 64 ) {}
    };

    class RIPEMD160 : public hash_t { public:
        RIPEMD160() : hash_t( MBEDTLS_MD_RIPEMD160, 20 ) {}
    };

}}
    
    /*─······································································─*/

namespace crypto { namespace hmac {

    class MD5 : public hmac_t { public:
          MD5 ( const string_t& key ) : hmac_t( key, MBEDTLS_MD_MD5, 16 ) {}
    };

    class SHA1 : public hmac_t { public:
          SHA1 ( const string_t& key ) : hmac_t( key, MBEDTLS_MD_SHA1, 20 ) {}
    };

    class SHA256 : public hmac_t { public:
          SHA256 ( const string_t& key ) : hmac_t( key, MBEDTLS_MD_SHA256, 32 ) {}
    };

    class SHA384 : public hmac_t { public:
          SHA384 ( const string_t& key ) : hmac_t( key, MBEDTLS_MD_SHA384, 48 ) {}
    };

    class SHA512 : public hmac_t { public:
          SHA512 ( const string_t& key ) : hmac_t( key, MBEDTLS_MD_SHA512, 64 ) {}
    };

    class SHA3_256 : public hmac_t { public:
          SHA3_256 ( const string_t& key ) : hmac_t( key, MBEDTLS_MD_SHA3_256, 32 ) {}
    };

    class SHA3_384 : public hmac_t { public:
          SHA3_384 ( const string_t& key ) : hmac_t( key, MBEDTLS_MD_SHA3_384, 48 ) {}
    };

    class SHA3_512 : public hmac_t { public:
          SHA3_512 ( const string_t& key ) : hmac_t( key, MBEDTLS_MD_SHA3_512, 64 ) {}
    };

    class RIPEMD160 : public hmac_t { public:
          RIPEMD160( const string_t& key ) : hmac_t( key, MBEDTLS_MD_RIPEMD160, 20 ) {}
    }; 

}}
    
    /*─······································································─*/

namespace crypto { namespace encrypt {

    class RSA : public rsa_t { public: template< class... T > 
          RSA ( const T&... args ) : rsa_t( args... ) {}
    };

    /*─······································································─*/
    
    class XOR : public xor_t { public: template< class... T >
          XOR ( const T&... args ) : xor_t( args... ) {}
    };

    /*─······································································─*/
    
    class DES_CBC : public encrypt_t { public: template< class... T >
          DES_CBC ( const T&... args ) : encrypt_t( args..., MBEDTLS_CIPHER_DES_CBC ) {}
    };
    
    class DES_ECB : public encrypt_t { public: template< class... T >
          DES_ECB ( const T&... args ) : encrypt_t( args..., MBEDTLS_CIPHER_DES_ECB ) {}
    };

    /*─······································································─*/
    
    class AES_128_CBC : public encrypt_t { public: template< class... T >
          AES_128_CBC( const T&... args ) : encrypt_t( args..., MBEDTLS_CIPHER_AES_128_CBC ) {}
    };
    
    class AES_192_CBC : public encrypt_t { public: template< class... T >
          AES_192_CBC( const T&... args ) : encrypt_t( args..., MBEDTLS_CIPHER_AES_192_CBC ) {}
    };
    
    class AES_256_CBC : public encrypt_t { public: template< class... T >
          AES_256_CBC( const T&... args ) : encrypt_t( args..., MBEDTLS_CIPHER_AES_256_CBC ) {}
    };

    /*─······································································─*/
    
    class AES_128_ECB : public encrypt_t { public: template< class... T >
          AES_128_ECB( const T&... args ) : encrypt_t( args..., MBEDTLS_CIPHER_AES_128_ECB ) {}
    };
    
    class AES_192_ECB : public encrypt_t { public: template< class... T >
          AES_192_ECB( const T&... args ) : encrypt_t( args..., MBEDTLS_CIPHER_AES_192_ECB ) {}
    };
    
    class AES_256_ECB : public encrypt_t { public: template< class... T >
          AES_256_ECB( const T&... args ) : encrypt_t( args..., MBEDTLS_CIPHER_AES_256_ECB ) {}
    };

    /*─······································································─*/
    
    class TRIPLE_DES_CBC : public encrypt_t { public: template< class... T >
          TRIPLE_DES_CBC ( const T&... args ) : encrypt_t( args..., MBEDTLS_CIPHER_DES_EDE3_CBC ) {}
    };
    
    class TRIPLE_DES_ECB : public encrypt_t { public: template< class... T >
          TRIPLE_DES_ECB ( const T&... args ) : encrypt_t( args..., MBEDTLS_CIPHER_DES_EDE3_ECB ) {}
    };

}}
    
    /*─······································································─*/

namespace crypto { namespace decrypt {

    class RSA : public rsa_t { public: template< class... T > 
          RSA ( const T&... args ) : rsa_t( args... ) {}
    };

    /*─······································································─*/
    
    class XOR : public xor_t { public: template< class... T >
          XOR ( const T&... args ) : xor_t( args... ) {}
    };

    /*─······································································─*/
    
    class DES_CBC : public decrypt_t { public: template< class... T >
          DES_CBC ( const T&... args ) : decrypt_t( args..., MBEDTLS_CIPHER_DES_CBC ) {}
    };
    
    class DES_ECB : public decrypt_t { public: template< class... T >
          DES_ECB ( const T&... args ) : decrypt_t( args..., MBEDTLS_CIPHER_DES_ECB ) {}
    };

    /*─······································································─*/
    
    class AES_128_CBC : public decrypt_t { public: template< class... T >
          AES_128_CBC( const T&... args ) : decrypt_t( args..., MBEDTLS_CIPHER_AES_128_CBC ) {}
    };
    
    class AES_192_CBC : public decrypt_t { public: template< class... T >
          AES_192_CBC( const T&... args ) : decrypt_t( args..., MBEDTLS_CIPHER_AES_192_CBC ) {}
    };
    
    class AES_256_CBC : public decrypt_t { public: template< class... T >
          AES_256_CBC( const T&... args ) : decrypt_t( args..., MBEDTLS_CIPHER_AES_256_CBC ) {}
    };

    /*─······································································─*/
    
    class AES_128_ECB : public decrypt_t { public: template< class... T >
          AES_128_ECB( const T&... args ) : decrypt_t( args..., MBEDTLS_CIPHER_AES_128_ECB ) {}
    };
    
    class AES_192_ECB : public decrypt_t { public: template< class... T >
          AES_192_ECB( const T&... args ) : decrypt_t( args..., MBEDTLS_CIPHER_AES_192_ECB ) {}
    };
    
    class AES_256_ECB : public decrypt_t { public: template< class... T >
          AES_256_ECB( const T&... args ) : decrypt_t( args..., MBEDTLS_CIPHER_AES_256_ECB ) {}
    };

    /*─······································································─*/
    
    class TRIPLE_DES_CBC : public decrypt_t { public: template< class... T >
          TRIPLE_DES_CBC ( const T&... args ) : decrypt_t( args..., MBEDTLS_CIPHER_DES_EDE3_CBC ) {}
    };
    
    class TRIPLE_DES_ECB : public decrypt_t { public: template< class... T >
          TRIPLE_DES_ECB ( const T&... args ) : decrypt_t( args..., MBEDTLS_CIPHER_DES_EDE3_ECB ) {}
    };

}}
    
    /*─······································································─*/

namespace crypto { namespace encoder {

    class BASE58 : public encoder_t { public:
          BASE58 () : encoder_t( "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" ) {}
    };

    class BASE16 : public encoder_t { public: 
          BASE16 () : encoder_t( "123456789ABCDEF" ){}
    };

    class BASE8 : public encoder_t { public: 
          BASE8 () : encoder_t( "1234567" ){}
    };

    class BASE4 : public encoder_t { public: 
          BASE4 () : encoder_t( "123" ){}
    };

    class BASE64 : public base64_encoder_t { public:
          BASE64 () : base64_encoder_t() {}
    };

}}
    
    /*─······································································─*/

namespace crypto { namespace decoder {

    class BASE58 : public decoder_t { public:
          BASE58 () : decoder_t( "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" ) {}
    };

    class BASE16 : public decoder_t { public: 
          BASE16 () : decoder_t( "123456789ABCDEF" ){}
    };

    class BASE8 : public decoder_t { public: 
          BASE8 () : decoder_t( "1234567" ){}
    };

    class BASE4 : public decoder_t { public: 
          BASE4 () : decoder_t( "123" ){}
    };

    class BASE64 : public base64_decoder_t { public:
          BASE64 () : base64_decoder_t() {}
    };

}}
    
    /*─······································································─*/

namespace crypto { namespace curve {
    
    class PRIME256V1 : public ec_t { public: template< class... T >
          PRIME256V1( const T&... args ) noexcept : ec_t( args..., MBEDTLS_ECP_DP_SECP256R1 ) {}
    };

    class PRIME192V1 : public ec_t { public: template< class... T >
          PRIME192V1( const T&... args ) noexcept : ec_t( args..., MBEDTLS_ECP_DP_SECP192R1 ) {}
    };

    class SECP256K1 : public ec_t { public: template< class... T >
          SECP256K1( const T&... args ) noexcept : ec_t( args..., MBEDTLS_ECP_DP_SECP256K1 ) {}
    };

}}
  
    /*─······································································─*/

}

#undef CRYPTO_BASE64
#endif