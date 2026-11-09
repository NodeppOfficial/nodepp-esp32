#include <nodepp.h>
#include <nodepp/wifi.h>
#include <nodepp/http.h>
#include <nodepp/ws.h>

using namespace nodepp;

void server() {

    auto client = queue_t<ws_t>();
    auto server = http::server([=]( http_t cli ){

        cli.write_header( 200, header_t({
            { "content-type", "text/html" }
        }) );

        cli.write( _STRING_(

            <h1> WebSocket Server on ESP32 </h1>
            <div>
                <input type="text" placeholder="message">
                <button submit> send </button>
            </div>
            <div></div>

            <script> window.addEventListener( "load", ()=>{
                var cli = new WebSocket( window.origin.replace( "http", "ws" ) );

                document.querySelector( "[submit]" ).addEventListener("click",()=>{
                    cli.send( document.querySelector("input").value );
                    document.querySelector("input").value = "";
                });

                cli.onmessage = ({data})=>{ 
                    var el = document.createElement("p");
                        el.innerHTML = data;
                    document.querySelector("div").appendChild( el ); 
                }

            } ) </script>

        ) );

    }); ws::server( server );

    server.onConnect([=]( ws_t cli ){ 

        client.push( cli ); auto ID = client.last();
        cli.onData([=]( string_t data ){
            client.map([&]( ws_t cli ){
                cli.write( data );
            }); console::log( "->", data );
        });

        cli.onDrain([=](){
            client.erase( ID );
            console::log( "closed" );
        }); console::log( "connected" );

    });

    process::add( coroutine::add( COROUTINE(){
    coBegin

        while( true ){
            coWait( Serial.available() );
        do {
            auto data = string_t( Serial.readString().c_str() );
        if ( data.empty() ){ break; }
            client.map([&]( ws_t cli ){ cli.write( data ); });
            console::log( "->", data );
        } while(0); coNext; }

    coFinish
    }));

    server.listen( "0.0.0.0", 8000, [=]( socket_t /*unused*/ ){
        console::log( ">> server started" );
    });

}

void onMain() {

    console::enable( 115200 );

    wifi::get_wifi_hal().onAPConnected([=]( ptr_t<uchar> mac ){
        console::log( ">> connected new device" );
    });

    wifi::get_wifi_hal().onAPDisconnected([=]( ptr_t<uchar> mac ){
        console::log( ">> disconencted device" );
    });

    wifi::turn_on();

    wifi::create_wifi_AP( "WIFI_AP", "0123456789", 0 )

    .then([=]( wifi_t device ) { server(); })

    .fail([=](except_t err) {
        console::log( err.what() );
    });

}