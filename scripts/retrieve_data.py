import requests
import json

import time





def get_interfaces(vyos_ip, key):
    vyos_api_url = f"https://{vyos_ip}/retrieve"
    payload = {
        'data': '{"op": "showConfig", "path": ["interfaces"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            interfaces_data = response.json()
            
            return interfaces_data
        else:
            print("Failed to retrieve interfaces. Status code:", response.status_code)
            return None
    except Exception as e:
        print("An error occurred while retrieving interfaces:", e)
        return None


def get_sys(vyos_ip, key):
    vyos_api_url = f"https://{vyos_ip}/retrieve"
    payload = {
        'data': '{"op": "showConfig", "path": ["system"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            interfaces_data = response.json()
            
            return interfaces_data
        else:
            print("Failed to retrieve sys infos. Status code:", response.status_code)
            return None
    except Exception as e:
        print("An error occurred while retrieving interfaces:", e)
        return None



def get_routing(vyos_ip, key):
    vyos_api_url = f"https://{vyos_ip}/retrieve"
    payload = {
        'data': '{"op": "showConfig", "path": ["protocols"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            print("Failed to retrieve routing information. Status code:", response.status_code)
            return response.status_code
    except Exception as e:
        print("An error occurred while retrieving routing information:", e)
        return e



def get_services(vyos_ip, key):
    vyos_api_url = f"https://{vyos_ip}/retrieve"
    payload = {
        'data': '{"op": "showConfig", "path": ["service"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            print("Failed to retrieve service information. Status code:", response.status_code)
            return None
    except Exception as e:
        print("An error occurred while retrieving service information:", e)
        return None


def get_https(vyos_ip, key):
    vyos_api_url = f"https://{vyos_ip}/retrieve"
    payload = {
        'data': '{"op": "showConfig", "path": ["service", "https"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            print("Failed to retrieve API information. Status code:", response.status_code)
            return None
    except Exception as e:
        print("An error occurred while retrieving service information:", e)
        return None



def get_nat(vyos_ip, key):
    vyos_api_url = f"https://{vyos_ip}/retrieve"
    payload = {
        'data': '{"op": "showConfig", "path": ["nat","source"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            interfaces_data = response.json()
            
            return interfaces_data
        else:
            print("Failed to retrieve NAT configuration. Status code:", response.status_code)
            return None
    except Exception as e:
        print("An error occurred while retrieving interfaces:", e)
        return None





def get_vpn(vyos_ip, key):
    vyos_api_url = f"https://{vyos_ip}/retrieve"
    payload = {
        'data': '{"op": "showConfig", "path": ["vpn"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            interfaces_data = response.json()
            
            return interfaces_data
        else:
            print("Failed to retrieve VPN configuration. Status code:", response.status_code)
            
            return None
    except Exception as e:
        print("An error occurred while retrieving interfaces:", e)
        return None
    


def get_firewall(vyos_ip, key):
    vyos_api_url = f"https://{vyos_ip}/retrieve"
    payload = {
        'data': '{"op": "showConfig", "path": ["firewall"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            interfaces_data = response.json()
            
            return interfaces_data
        else:
            print("Failed to retrieve VPN configuration. Status code:", response.status_code)
            return None
    except Exception as e:
        print("An error occurred while retrieving interfaces:", e)
        return None





def configure_interface(vyos_ip, key, int_type,interface_name, ip_address):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "set", "path": ["interfaces", "'+int_type+'", "' + interface_name + '", "address", "' + ip_address + '"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to configure interface. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False


def configure_vpn_auth(vyos_ip, key, authentication_name,authentified_id1, authentified_id2, secret_key):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '[{"op": "set", "path": ["vpn", "ipsec", "authentication", "psk", "' + authentication_name + '", "secret","' + secret_key + '"]}, {"op": "set", "path": ["vpn", "ipsec", "authentication", "psk", "' + authentication_name + '", "id","' + authentified_id1 + '"]}, {"op": "set", "path": ["vpn", "ipsec", "authentication", "psk", "' + authentication_name + '", "id","' + authentified_id2 + '"]}]',
                            
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to configure VPN authentication. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False



def configure_vpn_peer(vyos_ip, key, peer_name,remote_peer_id, remote_peer_address, local_peer_address, tunnel_id):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '[{"op": "set", "path": ["vpn", "ipsec", "site-to-site", "peer", "' + peer_name + '", "authentication", "mode", "pre-shared-secret"]}, {"op": "set", "path": ["vpn", "ipsec", "site-to-site", "peer", "' 
        + peer_name + '", "authentication", "remote-id", "'+ remote_peer_id +'"]},{"op": "set", "path": ["vpn", "ipsec", "site-to-site", "peer", "' 
        + peer_name + '", "default-esp-group", "MyESPGroup"]}, {"op": "set", "path": ["vpn", "ipsec", "site-to-site", "peer", "' 
        + peer_name + '", "ike-group", "MyIKEGroup"]}, {"op": "set", "path": ["vpn", "ipsec", "site-to-site", "peer", "' 
        + peer_name + '", "local-address", "'+ local_peer_address +'"]}, {"op": "set", "path": ["vpn", "ipsec", "site-to-site", "peer", "' 
        + peer_name + '", "remote-address", "'+ remote_peer_address +'"]}, {"op": "set", "path": ["vpn", "ipsec", "site-to-site", "peer", "' 
        + peer_name + '", "tunnel", "' + tunnel_id +'", "protocol", "gre"]}]',
                            
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to configure peer. Status code:", response.text)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False


# print(configure_vpn_peer('192.168.52.142', 'theKey', 'lePeer','leID2', '192.168.181.23', '192.168.52.158', '2'))

def configure_desc(vyos_ip, key, int_type, interface_name, description):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "set", "path": ["interfaces", "'+int_type+'", "' + interface_name + '", "description", "' + description + '"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to configure description. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False


def set_user(vyos_ip, key, username, password):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "set", "path": ["system", "login", "user","' + username + '", "authentication", "plaintext-password", "'+password+'"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to update user. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False


def del_user(vyos_ip, key, user):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "delete", "path": ["system", "login", "user","' + user + '"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to delete user. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False


def del_auth(vyos_ip, key, auth_name):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "delete", "path": ["vpn", "ipsec", "authentication", "psk","' + auth_name + '"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to delete user. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False


def del_peer(vyos_ip, key, peer_del):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "delete", "path": ["vpn", "ipsec", "site-to-site", "peer","' + peer_del + '"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to delete user. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False


def del_inbound(vyos_ip, key, in_rule_num):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "delete", "path": ["firewall", "ipv4", "input", "filter", "rule","' + in_rule_num + '"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to delete user. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False


def del_outbound(vyos_ip, key, out_rule_num):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "delete", "path": ["firewall", "ipv4", "output", "filter", "rule","' + out_rule_num + '"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to delete user. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False


def configure_fire_rule(vyos_ip, key, rule_type,fire_rule_num, rule_act, prot_port, rule_desc):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '[{"op": "set", "path": ["firewall", "ipv4", "'+rule_type+'", "filter", "rule","' 
        + fire_rule_num + '", "action","'+rule_act+'"]}, {"op": "set", "path": ["firewall", "ipv4", "'+rule_type+'", "filter", "rule","' 
        + fire_rule_num + '", "protocol", "tcp"]}, {"op": "set", "path": ["firewall", "ipv4", "'+rule_type+'", "filter", "rule","' 
        + fire_rule_num + '", "destination", "port","'+prot_port+'"]}, {"op": "set", "path": ["firewall", "ipv4", "'+rule_type+'", "filter", "rule","' 
        + fire_rule_num + '", "description","'+rule_desc+'"]}]',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to delete IP. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False



def add_int_tun(vyos_ip, key,tun_name, tun_add,remote_tun_address, source_tun_address):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '[{"op": "set", "path": ["interfaces", "tunnel", "'
        +tun_name+'", "encapsulation", "gre"]},{"op": "set", "path": ["interfaces", "tunnel", "'
        +tun_name+'", "address", "'+ tun_add +'"]}, {"op": "set", "path": ["interfaces", "tunnel", "'
        +tun_name+'", "remote", "'+ remote_tun_address  +'"]}, {"op": "set", "path": ["interfaces", "tunnel", "'
        +tun_name+'", "source-address", "'+ source_tun_address  +'"]}]',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to delete IP. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False


def delete_int_tun(vyos_ip, key, del_tun_name):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "delete", "path": ["interfaces", "tunnel", "' + del_tun_name + '"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to delete IP. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False





def delete_ip(vyos_ip, key, int_type,interface_name, ip_address):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "delete", "path": ["interfaces", "'+int_type+'", "' + interface_name + '", "address", "' + ip_address + '"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to delete IP. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False

def configure_routing(vyos_ip, key, net_route, route_next_hop):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "set", "path": ["protocols", "static", "route","'+ net_route +'", "next-hop", "'+ route_next_hop +'"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to configure route. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring route:", e)
        return False  


def configure_ssh(vyos_ip, key, listen_add):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "set", "path": ["service", "ssh", "listen-address","'+ listen_add +'"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to configure route. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring route:", e)
        return False  



def del_list_add(vyos_ip, key, lis_add):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "delete", "path": ["service", "ssh", "listen-address","'+ lis_add +'"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to configure route. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring route:", e)
        return False  




def delete_routing(vyos_ip, key, route_val):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "delete", "path": ["protocols", "static", "route","'+ route_val +'"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to delete route. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False
    





def configure_outbound(vyos_ip, key, rule_num, outbound_int):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "set", "path": ["nat", "source", "rule", "' + rule_num + '", "outbound-interface","name","' + outbound_int + '"]}',
        f'key': {key}
    }
    
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        print(response.text)
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False

def configure_source(vyos_ip, key, rule_num, source_address):
    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "set", "path": ["nat", "source", "rule", "' + rule_num + '", "source", "address","' + source_address + '"]}',
        f'key': {key}
    }

    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        print(response.text)
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return e

def configure_translation(vyos_ip, key, rule_num, trans_address):

    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "set", "path": ["nat", "source", "rule", "' + rule_num + '", "translation", "address","' + trans_address + '"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        print(response.text)
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False


def configure_nat(vyos_ip, key, rule_num, interface_name, source_address, trans_address):
    configure_translation(vyos_ip,key ,rule_num, trans_address)
    time.sleep(10)
    configure_source(vyos_ip, key, rule_num, source_address)
    time.sleep(10)
    configure_outbound(vyos_ip, key, rule_num, interface_name)




def del_rule(vyos_ip, key, rule_num):

    vyos_api_url = f"https://{vyos_ip}/configure"
    payload = {
        'data': '{"op": "delete", "path": ["nat", "source", "rule", "' + rule_num + '"]}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to delete rule. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False




def save_configuration(vyos_ip, key):
    vyos_api_url = f"https://{vyos_ip}/config-file"
    payload = {
        'data': '{"op": "save"}',
        f'key': {key}
    }
    headers = {}
    try:
        response = requests.post(vyos_api_url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return True
        else:
            print("Failed to save configuration. Status code:", response.status_code)
            return False
    except Exception as e:
        print("An error occurred while saving configuration:", e)
        return False
