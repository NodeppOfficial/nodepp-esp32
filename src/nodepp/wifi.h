#ifndef NODEPP_WIFI
#define NODEPP_WIFI

/*────────────────────────────────────────────────────────────────────────────*/

#if _KERNEL_ == NODEPP_KERNEL_ARDUINO
    #include "event.h"
    #include "promise.h"
    #include "optional.h"
    #include "arduino/wifi.h"
#else
    #error "This OS Does not support wifi.h"
#endif

/*────────────────────────────────────────────────────────────────────────────*/

namespace nodepp { namespace wifi {

    inline wifi_t& get_wifi_hal() { static wifi_t device; return device; }

    int cancel_scanning() { return get_wifi_hal().cancel_scanning(); }

    int remove_wifi_AP () { return get_wifi_hal().remove_wifi_AP(); }

    inline optional_t<wifi_device_t>
    get_wifi_device() { return get_wifi_hal().get_wifi_device(); }

    inline promise_t< ptr_t<wifi_device_t>, except_t >
    scan() { return get_wifi_hal().scan(); }

    inline promise_t< wifi_device_t, except_t >
    connect_wifi_AP( string_t ssid, string_t pass ){
        return get_wifi_hal().connect_wifi_AP( ssid, pass );
    }

    inline promise_t< wifi_t, except_t > 
    create_wifi_AP( string_t ssid, string_t pass, uint8 channel ){
        return get_wifi_hal().create_wifi_AP( ssid, pass, channel );
    }

    int disconnect_wifi_AP() { return get_wifi_hal().disconnect_wifi_AP(); }

} }

/*────────────────────────────────────────────────────────────────────────────*/

#endif