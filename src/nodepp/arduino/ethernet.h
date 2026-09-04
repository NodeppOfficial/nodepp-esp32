
/*

        ETH_STATE_UNKNOWN         = 0b00000000,
        ETH_STATE_START           = 0b00000010,
        ETH_STATE_STOP            = 0b00000100,
        ETH_STATE_CONNECTED       = 0b00001000,
        ETH_STATE_DISONECTED      = 0b00010000,
        IP_STATE_ETH_GOT_IP       = 0b00001000,
        IP_STATE_ETH_LOST_IP      = 0b00010000,

    event_t<> onETHStop ;
    event_t<> onETHStart;
    event_t<> onETHConnected;
    event_t<> onETHDisconnected;

void init_ethernet() {
    // 1. Inicializar la interfaz de red TCP/IP (Solo una vez)
    // esp_netif_init(); 

    // 2. Crear la configuración por defecto para Ethernet
    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&cfg);

    // 3. Configurar el Hardware (MAC y PHY)
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    
    // Aquí defines qué chip usas (LAN8720 es el más común)
    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&mac_config, &phy_config);
    esp_eth_phy_t *phy = esp_eth_phy_new_lan8720(&phy_config);

    // 4. Instalar y Arrancar
    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    esp_eth_driver_install(&eth_config, &eth_handle);

    // 5. Vincular el Driver de ETH con el Stack TCP/IP de Espressif
    esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle));

    // 6. ¡Fuego! Esto activa las interrupciones de hardware
    esp_eth_start(eth_handle); 
}
*/