Le format des requêtes DHCP est sous la forme d'une liste de dictionnaires.
Le format des options DHCP est sous la forme d'un dictionnaire imbriqué.

La fonction config_server() permet de charger le fichier config_file_name (conf.txt) qui contient les informations nécessaires au fonctionnement du serveur DHCP.

La fonction data_decoder() permet de décomposer les requêtes DHCP sous la forme d'une liste de dictionnaires.

La fonction options_decoder() permet de décomposer les requêtes DHCP sous la forme d'une liste de dictionnaires.

La fonction options_translator() permet de traduire et de formater les options.

La fonction string_to_byte() permet de transformer les string en hexadécimal.

La fonction check_message_type() permet de vérifier le type du message (DISCOVER, OFFER, REQUEST, ACK).

La fonction dhcp_offer() permet de créer la réponse dhcp OFFER au client.

La fonction dhcp_ack() permet de créer la réponse dhcp ACK au client.

La fonction ip_selection() permet de vérifier si l'IP générée est valide.

La fonction random_ip_generator() permet de générer une IP dans une intervalle donnée.

La fonction ips() permet d'initialiser une liste IP dans la plage indiquée.

La fonction log_update() permet de mettre à jour le fichier log_file.txt correspondant à l'historique du serveur.

La fonction log_database_update() permet de mettre à jour le fichier database.txt correspondant à l'état des IP.

La fonction handle_client() permet de gérer la requête reçue par le client.

La fonction clear_ip_state_list() permet de libérer les ip dont le bail est expiré.

La fonction start() permet de gérer les requêtes reçues et envoie les réponses aux clients correspondants.
