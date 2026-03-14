/*
 * Copyright 2023 The Nodepp Project Authors. All Rights Reserved.
 *
 * Licensed under the MIT (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/NodeppOfficial/nodepp/blob/main/LICENSE
 */

/*────────────────────────────────────────────────────────────────────────────*/

#ifndef NODEPP_ARDUINO_WIFI
#define NODEPP_ARDUINO_WIFI

/*────────────────────────────────────────────────────────────────────────────*/

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_netif.h>
#include <nvs_flash.h>

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp { struct wifi_device_t {

    ptr_t<uchar>/**/ mac     ;
    string_t /*---*/ name    ;
    uint8 /*------*/ channel ;
    uint8 /*------*/ antenna ;
    uint8 /*------*/ strength;
//  uint8 /*------*/ bandwith;
    wifi_auth_mode_t auth_mode;
 
}; }

namespace nodepp { namespace wifi { enum ANTENNA {

    WIFI_ANTENNA_0       = WIFI_ANT_ANT0,
    WIFI_ANTENNA_1       = WIFI_ANT_ANT1,
    WIFI_ANTENNA_INVALID = WIFI_ANT_MAX

};}}

namespace nodepp { namespace wifi { enum AUTHMODE {

    WIFI_AUTHMODE_MAX                 = WIFI_AUTH_MAX ,
    WIFI_AUTHMODE_OPEN                = WIFI_AUTH_OPEN,
    WIFI_AUTHMODE_DPP                 = WIFI_AUTH_DPP ,
    WIFI_AUTHMODE_WEP                 = WIFI_AUTH_WEP ,
    WIFI_AUTHMODE_OWE                 = WIFI_AUTH_OWE ,

    WIFI_AUTHMODE_WPA_PSK             = WIFI_AUTH_WPA_PSK,
    WIFI_AUTHMODE_WAPI_PSK            = WIFI_AUTH_WAPI_PSK,
    WIFI_AUTHMODE_WPA2_PSK            = WIFI_AUTH_WPA_WPA2_PSK,
    WIFI_AUTHMODE_WPA2_WPA3_PSK       = WIFI_AUTH_WPA2_WPA3_PSK,

    WIFI_AUTHMODE_WPA3_PSK            = WIFI_AUTH_WPA3_PSK,
    WIFI_AUTHMODE_WPA3_ENT_192        = WIFI_AUTH_WPA3_ENT_192,
    WIFI_AUTHMODE_WPA3_EXT_PSK        = WIFI_AUTH_WPA3_EXT_PSK,
    WIFI_AUTHMODE_WPA3_EXT_PSK_MIX    = WIFI_AUTH_WPA3_EXT_PSK_MIXED_MODE,

    WIFI_AUTHMODE_ENTERPRISE          = WIFI_AUTH_ENTERPRISE,
    WIFI_AUTHMODE_WPA_ENTERPRISE      = WIFI_AUTH_WPA_ENTERPRISE ,
    WIFI_AUTHMODE_WPA2_ENTERPRISE     = WIFI_AUTH_WPA2_ENTERPRISE,
    WIFI_AUTHMODE_WPA3_ENTERPRISE     = WIFI_AUTH_WPA3_ENTERPRISE,
    WIFI_AUTHMODE_WPA2_WPA3_ENTERPRISE= WIFI_AUTH_WPA2_WPA3_ENTERPRISE

};}}

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp { class wifi_t {
private:

    enum STATE {
        
        WIFI_STATE_CONNECTED    = 0b00000001,
        WIFI_STATE_UNKNOWN      = 0b00000000,
        WIFI_STATE_FAIL         = 0b00000010,
        WIFI_STATE_WAITING      = 0b00000100,
        WIFI_STATE_SUCCESS      = 0b00001000,
        WIFI_STATE_DISCONNECTED = 0b00010000,

    };

    struct NODE {

        esp_event_handler_instance_t ev; 
        wifi_init_config_t cfg; 
        int state = 0;

       ~NODE() { 
            esp_event_handler_instance_unregister( 
                WIFI_EVENT, ESP_EVENT_ANY_ID, &ev
            );
        }

    };  ptr_t<NODE> obj;

    ptr_t<wifi_device_t> get_detected_devices( uint16_t& count ) const noexcept {
    if( count == 0 ){ return nullptr; }

        auto device = ptr_t<wifi_device_t>   (count);
        auto raw    = ptr_t<wifi_ap_record_t>(count);

        esp_wifi_scan_get_ap_records( &count, &raw );

        for( int x=count; x-->0; )
           { device[x] = get_wifi_device( raw[x] ); }

    return device; }

    /*─······································································─*/

    bool& wifi_device_ctx() const noexcept { static bool out = false; return out; }

    /*─······································································─*/

    wifi_device_t get_wifi_device( wifi_ap_record_t& raw ) const noexcept {

        wifi_device_t device = {};

        device.name      = string_t( (char*)raw.ssid, strlen((char*)raw.ssid) );
        device.mac       = ptr_t<uchar>( 6UL ); 
        device.auth_mode = raw.authmode;
        device.strength  = raw.rssi;
        device.antenna   = raw.ant;

        device.mac.fill( raw.bssid, 6UL );

    return device; }

    /*─······································································─*/

    static void EVLOOP_CLB( void* arg, esp_event_base_t ev_base, int32_t id, void* data ){
    if( arg==nullptr ){ return; } auto self = type::cast<wifi_t>( arg );
    if( ev_base == WIFI_EVENT ){ switch(id){

        case WIFI_EVENT_STA_CONNECTED: do {
            self->obj->state = WIFI_STATE_CONNECTED;
            auto raw = self->get_wifi_device(); 
        if( !raw.has_value() ){ break; }
            self->onWifiConnected.emit( raw.value() ); 
        } while(0); break;

        case WIFI_EVENT_STA_DISCONNECTED: do {
            self->obj->state = WIFI_STATE_DISCONNECTED;
            self->onWifiDisconnected.emit(); 
        } while(0); break;

        case WIFI_EVENT_AP_STACONNECTED : do {
            auto raw =(wifi_event_ap_staconnected_t*) data;
            auto mac = ptr_t<uchar>( 6UL );
                 mac.fill( raw->mac, 6UL );
            self->onAPConnected.emit( mac ); 
        } while(0); break;

        case WIFI_EVENT_AP_STADISCONNECTED: do {
            auto raw =(wifi_event_ap_stadisconnected_t*) data;
            auto mac = ptr_t<uchar>( 6UL );
                 mac.fill( raw->mac, 6UL );
            self->onAPDisconnected.emit( mac ); 
        } while(0); break;

        case WIFI_EVENT_SCAN_DONE: do {
            uint16_t count   = 0; esp_wifi_scan_get_ap_num( &count );
            self->obj->state = count==0 ? WIFI_STATE_FAIL
            /*-----------------------*/ : WIFI_STATE_SUCCESS; 
        } while(0); break;

    }}}

public:

    event_t<ptr_t<uchar>>         onAPDisconnected  ;  
    event_t<wifi_device_t>        onWifiConnected   ;
    event_t<ptr_t<uchar>>         onAPConnected     ;
    event_t<>                     onWifiDisconnected;

    /*─······································································─*/

   ~wifi_t() noexcept { if( obj.count()>1 ){ return; } free(); }

    wifi_t() noexcept : obj( new NODE() ) {

        turn_on();
        
        esp_event_handler_instance_register( 
            WIFI_EVENT, ESP_EVENT_ANY_ID, 
            EVLOOP_CLB, this, &obj->ev
        );

    obj->state = STATE::WIFI_STATE_UNKNOWN; }
    
    /*─······································································─*/

    void free() const noexcept { 
        onAPConnected  .clear(); onAPDisconnected  .clear();
        onWifiConnected.clear(); onWifiDisconnected.clear(); 
    esp_wifi_stop(); }

    /*─······································································─*/

    int turn_on() const noexcept { auto ctx = &wifi_device_ctx();

        if( !(*ctx) ){ *ctx = true;

            auto c = nvs_flash_init();

            if( c==ESP_ERR_NVS_NO_FREE_PAGES     ||
                c==ESP_ERR_NVS_NEW_VERSION_FOUND
            ) {
                nvs_flash_erase();
                nvs_flash_init ();
            }

            memset( &obj->cfg, 0, sizeof(wifi_init_config_t) );
            esp_netif_init(); esp_event_loop_create_default(); 
            esp_netif_create_default_wifi_sta(); 
            esp_netif_create_default_wifi_ap (); 

            obj->cfg = WIFI_INIT_CONFIG_DEFAULT();
            esp_wifi_init( &obj->cfg );

        }
    
    return *ctx==false ? -1 : 1; }

    int turn_off() const noexcept { auto ctx = &wifi_device_ctx();

        if( !(*ctx) ){ *ctx = false; 
            esp_netif_deinit();
            esp_wifi_deinit ();
        }

    return *ctx==true ? -1 : 1; }

    /*─······································································─*/

    int remove_wifi_AP() const noexcept { 
        if( esp_wifi_stop() != ESP_OK ){ return -1; }
        obj->state = WIFI_STATE_UNKNOWN;
    return 1; }

    int cancel_scanning() const noexcept {
        if( esp_wifi_scan_stop() != ESP_OK ){ return -1; }
        obj->state = WIFI_STATE_UNKNOWN;
    return 1; }

    int disconnect_wifi_AP() const noexcept {
        if( esp_wifi_disconnect() != ESP_OK ){ return -1; }
        obj->state = WIFI_STATE_UNKNOWN;
    return 1; }

    /*─······································································─*/

    optional_t<wifi_device_t> 
    get_wifi_device() const noexcept {

        wifi_ap_record_t raw; wifi_device_t device;

        if( esp_wifi_sta_get_ap_info(&raw) != ESP_OK )
          { return nullptr; }

        return get_wifi_device( raw );

    }

    /*─······································································─*/

    promise_t< wifi_t, except_t >
    create_wifi_AP( string_t ssid, string_t pass, uint8 channel ) const noexcept {
           auto self = type::bind( this );
    return promise_t<wifi_t,except_t> ([=]( res_t<wifi_t> res, rej_t<except_t> rej ){

        if( self->obj->state & STATE::WIFI_STATE_WAITING ){ 
            rej( except_t( "wifi device already used" ) ); 
        return; } 

        wifi_config_t wifi_cfg;
        memset( &wifi_cfg, 0, sizeof(wifi_config_t));

        wifi_cfg.ap.channel        = channel   ;
        wifi_cfg.ap.max_connection = MAX_SOCKET;
        wifi_cfg.ap.authmode       = pass.empty()?WIFI_AUTH_OPEN:WIFI_AUTH_WPA2_PSK;
        memcpy( wifi_cfg.ap.ssid, ssid.get(), min( (uchar)32, (uchar)ssid.size() ));

        if( !pass.empty() ){
            memcpy( wifi_cfg.ap.password, pass.get(), min( (uchar)32, (uchar)pass.size() ));
        }   
        
        esp_wifi_set_mode  ( WIFI_MODE_AP ); 
        esp_wifi_set_config( WIFI_IF_AP, &wifi_cfg );

        if( esp_wifi_start() != ESP_OK ){ 
            self->remove_wifi_AP(); /*----------------------*/
            rej( except_t( "can't connect the wifi device" ) ); 
        return; }

        self->obj->state |= STATE::WIFI_STATE_WAITING; res( *self );

    }); }

    /*─······································································─*/

    promise_t< wifi_device_t, except_t >
    connect_wifi_AP( string_t ssid, string_t pass, ulong timeout=60000 ) const noexcept {
           auto self = type::bind( this );
    return promise_t<wifi_device_t,except_t> ([=]( res_t<wifi_device_t> res, rej_t<except_t> rej ){

        if( self->obj->state & STATE::WIFI_STATE_WAITING ){ 
            rej( except_t( "wifi device already used" ) ); 
        return; }

        wifi_config_t wifi_cfg;
        memset( &wifi_cfg, 0, sizeof(wifi_config_t));
        memcpy( wifi_cfg.sta.ssid    , ssid.get(), min( (uchar)32, (uchar)ssid.size() ));
        memcpy( wifi_cfg.sta.password, pass.get(), min( (uchar)32, (uchar)pass.size() ));

        self->obj->state &=~ WIFI_STATE_DISCONNECTED;
        self->obj->state &=~ WIFI_STATE_CONNECTED   ;
        self->obj->state |=  WIFI_STATE_WAITING     ;

        esp_wifi_set_mode  ( WIFI_MODE_STA );
        esp_wifi_set_config( WIFI_IF_STA, &wifi_cfg );

        if( esp_wifi_start() != ESP_OK ){
            self->disconnect_wifi_AP(); /*----------------*/
            rej( except_t( "can't start the wifi device" ) ); 
        return; }

        if( esp_wifi_connect() != ESP_OK ){ 
            self->disconnect_wifi_AP(); /*------------------*/
            rej( except_t( "can't connect the wifi device" ) ); 
        return; }

        ptr_t<ulong> stamp ( 0UL, timeout==0? 0UL : timeout + process::now() );
        process::add( coroutine::add( COROUTINE(){

            if( *stamp!=0 && process::now() > *stamp ){
                self->disconnect_wifi_AP(); /*---------*/
                rej( "wifi connecting timeout reached" ); 
            return -1; }

            if( self->obj->state == WIFI_STATE_UNKNOWN ){
                self->disconnect_wifi_AP(); /*-*/
                rej( "operation was cancelled" );
            return -1; }
            
        coBegin

            coWait( 
                ( self->obj->state & WIFI_STATE_CONNECTED    )==0 &&
                ( self->obj->state & WIFI_STATE_DISCONNECTED )==0
            );

            if( self->obj->state & WIFI_STATE_CONNECTED ){
                auto raw = self->get_wifi_device();
            if( !raw.has_value() ){ rej( "coudn't connect the wifi_device" ); }
            else /*------------*/ { res( raw.value() ); }}

            elif( self->obj->state & WIFI_STATE_DISCONNECTED ){ 
                self->disconnect_wifi_AP(); /*---------*/
                rej( "coudn't connect the wifi_device" ); 
            coEnd; }

        coFinish
        }));
    
    }); }

    /*─······································································─*/

    promise_t< ptr_t<wifi_device_t>, except_t > scan( ulong timeout=60000 ) const noexcept {
           auto self = type::bind( this );
    return promise_t< ptr_t<wifi_device_t>, except_t > ([=]( 
        res_t< ptr_t<wifi_device_t> > res, rej_t<except_t> rej 
    ){

        if( self->obj->state & STATE::WIFI_STATE_WAITING ){ 
            rej( except_t( "wifi device already used" ) ); 
        return; }

        self->obj->state &=~ WIFI_STATE_FAIL   ;
        self->obj->state &=~ WIFI_STATE_SUCCESS;
        self->obj->state |=  WIFI_STATE_WAITING;
        wifi_scan_config_t scan_config={ };

        esp_wifi_set_mode( WIFI_MODE_STA );

        if( esp_wifi_start() != ESP_OK ){
            self->disconnect_wifi_AP(); /*----------------*/
            rej( except_t( "can't start the wifi device" ) ); 
        return; }

        if( esp_wifi_scan_start( &scan_config, false ) != ESP_OK ){
            cancel_scanning(); /*---------------*/
            rej(except_t("Scan failed to start"));
        return; }

        ptr_t<ulong> stamp ( 0UL, timeout==0? 0UL : timeout + process::now() );
        process::add( coroutine::add( COROUTINE(){

            if( *stamp!=0 && process::now() > *stamp ){ 
                cancel_scanning(); /*----------------*/
                rej( "wifi scanning timeout reached" ); 
            return -1; }

            if( self->obj->state == WIFI_STATE_UNKNOWN ){
                cancel_scanning(); /*----------*/
                rej( "operation was cancelled" );
            return -1; }

        coBegin

            coWait( 
                ( self->obj->state & WIFI_STATE_SUCCESS )==0 &&
                ( self->obj->state & WIFI_STATE_FAIL    )==0 
            );

            if( self->obj->state &  WIFI_STATE_FAIL   ){ 
                cancel_scanning(); /*------------------*/
                rej( except_t( "no wifi devices founded" ) ); 
            coEnd; }

            do {
                
                uint16_t ap_count = 0; 
                self->obj->state &=~WIFI_STATE_UNKNOWN;
                esp_wifi_scan_get_ap_num ( &ap_count );
                res( self->get_detected_devices( ap_count ));

            } while(0); self->cancel_scanning();

        coFinish
        }));

    }); }

};}

/*────────────────────────────────────────────────────────────────────────────*/

#endif

/*────────────────────────────────────────────────────────────────────────────*/