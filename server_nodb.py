import scripts.retrieve_data as retrieve_data

from flask import Flask, render_template, request, redirect, url_for, jsonify, session

import time
import urllib3

import requests
app = Flask(__name__)
app.secret_key = 'wail'



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
@app.route('/')
def enter_ip():
    
    return render_template('enter_manual_ip.html')



@app.route('/submit_ip', methods=['POST'])
def submit_ip():
    # Get the selected IP address and VM ID from the form
    selected_ip = request.form['vyos_ip']
    key = request.form['key']
    session['vyos_ip'] = selected_ip
    session['key'] = key
    # Check if the selected IP address is "No IP"
    
    return redirect(url_for('index', vyos_ip=selected_ip))




# Route to handle manual IP address submission
@app.route('/submit_manual_ip', methods=['POST'])
def submit_manual_ip():
    # Get the manually entered IP address from the form
    manual_ip = request.form['manual_ip']
    key = request.form['key']
    session['vyos_ip'] = manual_ip
    session['key'] = key
    # Redirect to the VyOS management page with the manually entered IP address
    return redirect(url_for('index', vyos_ip=manual_ip))


@app.route('/index')
def index():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    if not vyos_ip:
        # Handle the case where vyos_ip is not available in session
        # Redirect or show an error message
        return redirect(url_for('submit_ip'))  # Redirect to manual IP entry page or wherever appropriate
    
    interfaces_data = retrieve_data.get_interfaces(vyos_ip, key)
        
    services_data = retrieve_data.get_services(vyos_ip, key)
    # if not interfaces_data:
    #     vm_info = fetch_vm_info()
    #     message = 'VyOS instance not fully booted'
    #     return redirect(url_for('enter_ip', message = message))
    # else:
    while not interfaces_data:
        interfaces_data = retrieve_data.get_interfaces(vyos_ip, key)       
        services_data = retrieve_data.get_services(vyos_ip, key)
        
    return render_template('index.html', interfaces_data=interfaces_data, services_data=services_data,vyos_ip=vyos_ip)





@app.route('/routing')
def routing():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    if not vyos_ip:
        # Handle the case where vyos_ip is not available in session
        # Redirect or show an error message
        return redirect(url_for('submit_ip'))  # Redirect to manual IP entry page or wherever appropriate
    routing_data = retrieve_data.get_routing(vyos_ip, key)
    return render_template('routing_page.html', routing_data=routing_data)


@app.route('/https')
def https():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    if not vyos_ip:
        # Handle the case where vyos_ip is not available in session
        # Redirect or show an error message
        return redirect(url_for('submit_ip'))  # Redirect to manual IP entry page or wherever appropriate
    services_data = retrieve_data.get_services(vyos_ip, key)
    https_data = retrieve_data.get_https(vyos_ip, key)
    return render_template('https_page.html', https_data=https_data, services_data = services_data)


@app.route('/ntp')
def ntp():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    if not vyos_ip:
        # Handle the case where vyos_ip is not available in session
        # Redirect or show an error message
        return redirect(url_for('submit_ip'))  # Redirect to manual IP entry page or wherever appropriate
    services_data = retrieve_data.get_services(vyos_ip, key)
    return render_template('ntp_page.html', services_data = services_data)


@app.route('/ssh')
def ssh():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    if not vyos_ip:
        # Handle the case where vyos_ip is not available in session
        # Redirect or show an error message
        return redirect(url_for('submit_ip'))  # Redirect to manual IP entry page or wherever appropriate
    services_data = retrieve_data.get_services(vyos_ip, key)
    return render_template('ssh_page.html', services_data = services_data)

@app.route('/nat')
def nat():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    if not vyos_ip:
        # Handle the case where vyos_ip is not available in session
        # Redirect or show an error message
        return redirect(url_for('submit_ip'))  # Redirect to manual IP entry page or wherever appropriate
    interfaces_data = retrieve_data.get_interfaces(vyos_ip, key)
    nat_data = retrieve_data.get_nat(vyos_ip, key)
    return render_template('nat_page.html', interfaces_data=interfaces_data, nat_data = nat_data)



@app.route('/vpn')
def vpn():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    if not vyos_ip:
        # Handle the case where vyos_ip is not available in session
        # Redirect or show an error message
        return redirect(url_for('submit_ip'))  # Redirect to manual IP entry page or wherever appropriate
    # interfaces_data = retrieve_data.get_interfaces(vyos_ip, key)
    data = retrieve_data.get_vpn(vyos_ip, key)['data']
    authentications = data['ipsec']['authentication']['psk']
    site2site = data['ipsec']['site-to-site']
    peers = site2site['peer']
    return render_template('vpn_page.html', vpn_data = data, authentications = authentications, peers = peers)



@app.route('/firewall')
def firewall():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    if not vyos_ip:
        # Handle the case where vyos_ip is not available in session
        # Redirect or show an error message
        return redirect(url_for('submit_ip'))  # Redirect to manual IP entry page or wherever appropriate
    # interfaces_data = retrieve_data.get_interfaces(vyos_ip, key)
    firewall_data = retrieve_data.get_firewall(vyos_ip, key)['data']['ipv4']
    
    if 'rule' in firewall_data['input']['filter']:
        inbound_rules = firewall_data['input']['filter']['rule']
        
    else:
        inbound_rules = None
        
    
    
    if 'rule' in firewall_data['output']['filter']:
        outbound_rules = firewall_data['output']['filter']['rule']       
    else:
        outbound_rules = None
        
    
    return render_template('firewall_page.html', firewall_data = firewall_data, inbound_rules = inbound_rules, outbound_rules = outbound_rules)

    

@app.route('/system_info')
def system_info():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    if not vyos_ip:
        # Handle the case where vyos_ip is not available in session
        # Redirect or show an error message
        return redirect(url_for('submit_ip'))  # Redirect to manual IP entry page or wherever appropriate
    users = retrieve_data.get_sys(vyos_ip, key)['data']['login']
    return render_template('sys_man.html', users = users)




@app.route('/del_user', methods=['POST'])
def del_user():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    username = request.form['username']
    
    success = retrieve_data.del_user(vyos_ip, key, username)
    if success:
        return jsonify({'message': 'User deleted successfully successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to delete user. Please check the logs for more information.', 'success': False})


@app.route('/del_auth', methods=['POST'])
def del_auth():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    auth_name = request.form['auth_name']
    
    success = retrieve_data.del_auth(vyos_ip, key, auth_name)
    if success:
        return jsonify({'message': 'Authentication deleted successfully successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to delete user. Please check the logs for more information.', 'success': False})


@app.route('/del_peer', methods=['POST'])
def del_peer():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    peer_del = request.form['peer_del']
    
    success = retrieve_data.del_peer(vyos_ip, key, peer_del)
    if success:
        return jsonify({'message': 'VPN peer deleted successfully successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to delete user. Please check the logs for more information.', 'success': False})



@app.route('/del_inbound', methods=['POST'])
def del_inbound():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    in_rule_num = request.form['in_rule_num']
    
    success = retrieve_data.del_inbound(vyos_ip, key, in_rule_num)
    if success:
        return jsonify({'message': 'Firewall rule deleted successfully successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to delete rule. Please check the logs for more information.', 'success': False})



@app.route('/del_outbound', methods=['POST'])
def del_outbound():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    out_rule_num = request.form['out_rule_num']
    
    success = retrieve_data.del_outbound(vyos_ip, key, out_rule_num)
    if success:
        return jsonify({'message': 'Firewall rule deleted successfully successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to delete rule. Please check the logs for more information.', 'success': False})


@app.route('/set_user', methods=['POST'])
def set_user():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    username = request.form['username']
    password = request.form['password']
    
    success = retrieve_data.set_user(vyos_ip, key, username, password)
    if success:
        return jsonify({'message': 'User added successfully successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to add user. Please check the logs for more information.', 'success': False})


@app.route('/configure_interface', methods=['POST'])
def configure_interface():
    vyos_ip = request.form['vyos_ip']
    key = session.get('key', None)
    interface_name = request.form['interface_name']
    ip_address = request.form['ip_address']
    if interface_name.startswith('eth'):
        int_type = "ethernet"

    elif interface_name.startswith('lo'):
        int_type = "loopback"
    else:
        int_type = "tunnel"
    success = retrieve_data.configure_interface(vyos_ip, key, int_type,interface_name, ip_address)
    if success:
        return jsonify({'message': 'Interface configuration submitted successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to configure interface. Please check the logs for more information.', 'success': False})


@app.route('/add_int_tun', methods=['POST'])
def add_int_tun():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    tun_name = request.form['tun_name']
    tun_add = request.form['tun_add']
    remote_tun_address = request.form['remote_tun_address']
    source_tun_address = request.form['source_tun_address']
    
    success = retrieve_data.add_int_tun(vyos_ip, key,tun_name, tun_add,remote_tun_address, source_tun_address)
    if success:
        return jsonify({'message': 'Interface configuration submitted successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to configure interface. Please check the logs for more information.', 'success': False})



@app.route('/delete_int_tun', methods=['POST'])
def delete_int_tun():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    del_tun_name = request.form['del_tun_name']
    
    
    success = retrieve_data.delete_int_tun(vyos_ip, key, del_tun_name)
    if success:
        return jsonify({'message': 'Interface tunnel  deleted successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to configure interface. Please check the logs for more information.', 'success': False})


@app.route('/configure_authentication', methods=['POST'])
def configure_authentication():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    authentication_name = request.form['authentication_name']
    authentified_id1 = request.form['authentified_id1']
    authentified_id2 = request.form['authentified_id2']
    secret_key = request.form['secret_key']
    success = retrieve_data.configure_vpn_auth(vyos_ip, key, authentication_name,authentified_id1, authentified_id2, secret_key)
    if success:
        return jsonify({'message': 'VPN authentication submitted successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to configure interface. Please check the logs for more information.', 'success': False})

@app.route('/configure_peer', methods=['POST'])
def configure_peer():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    peer_name = request.form['peer_name']
    remote_peer_id = request.form['remote_peer_id']
    remote_peer_address = request.form['remote_peer_address']
    local_peer_address = request.form['local_peer_address']
    tunnel_id = request.form['tunnel_id']
    success = retrieve_data.configure_vpn_peer(vyos_ip, key, peer_name,remote_peer_id, remote_peer_address, local_peer_address, tunnel_id)
    if success:
        return jsonify({'message': 'VPN authentication submitted successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to configure interface. Please check the logs for more information.', 'success': False})



@app.route('/add_rule', methods=['POST'])
def configure_fire_rule():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    rule_type = request.form['rule_type']
    fire_rule_num = request.form['fire_rule_num']
    rule_act = request.form['rule_act']
    prot_port = request.form['prot_port']
    rule_desc = request.form['rule_desc']
    success = retrieve_data.configure_fire_rule(vyos_ip, key, rule_type,fire_rule_num, rule_act, prot_port, rule_desc)
    if success:
        return jsonify({'message': 'Firewall rule submitted successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to configure rule. Please check the logs for more information.', 'success': False})


@app.route('/configure_routing', methods=['POST'])
def configure_routing():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    
    net_route = request.form['net_route']
    route_next_hop = request.form['route_next_hop']
    
    success = retrieve_data.configure_routing(vyos_ip, key ,net_route, route_next_hop)
    if success:
        return jsonify({'message': 'Route submitted successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to configure route. Please check the logs for more information.', 'success': False})


@app.route('/delete_routing', methods=['POST'])
def delete_routing():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    route_val = request.form['route_val']
    
    
    success = retrieve_data.delete_routing(vyos_ip, key, route_val)
    if success:
        return jsonify({'message': 'Route deleted successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to configure route. Please check the logs for more information.', 'success': False})



@app.route('/configure_ssh', methods=['POST'])
def configure_ssh():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    listen_add = request.form['listen_add']
    
    
    success = retrieve_data.configure_ssh(vyos_ip, key, listen_add)
    if success:
        return jsonify({'message': 'Listen address configured successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to configure listen address. Please check the logs for more information.', 'success': False})


@app.route('/del_list_add', methods=['POST'])
def configudel_list_addre_ssh():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    lis_add = request.form['lis_add']
    
    
    success = retrieve_data.del_list_add(vyos_ip, key, lis_add)
    if success:
        return jsonify({'message': 'Listen address deleted successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to delete listen address. Please check the logs for more information.', 'success': False})


@app.route('/configure_desc', methods=['POST'])
def configure_desc():
    vyos_ip = request.form['vyos_ip']
    key = session.get('key', None)
    interface_name = request.form['interface_name']
    description = request.form['description']
    if interface_name.startswith('eth'):
        int_type = "ethernet"
    else:
        int_type = "loopback"
    
    
    success = retrieve_data.configure_desc(vyos_ip, key, int_type, interface_name, description)
    if success:
        return jsonify({'message': 'Interface description submitted successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to configure interface description. Please check the logs for more information.', 'success': False})

@app.route('/delete_ip', methods=['POST'])
def delete_ip():
    
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    interface_name = request.form['interface_name']
    ip_address = request.form['ip_address']   

    if interface_name.startswith('eth'):
        int_type = "ethernet"

    elif interface_name.startswith('lo'):
        int_type = "loopback"
    else:
        int_type = "tunnel"
    success = retrieve_data.delete_ip(vyos_ip, key, int_type,interface_name, ip_address)
        
    if success:
        return jsonify({'message': 'IP address deleted successfully.', 'success': True})
    else:
        return jsonify({'message': 'Failed to delete IP address. Please check the logs for more information.', 'success': False})




@app.route('/configure_nat', methods=['POST'])
def configure_nat():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    rule_num = request.form['rule_num']
    outbound_int = request.form['outbound_int']
    source_address = request.form['source_address']
    trans_address = request.form['trans_address']
    retrieve_data.configure_nat(vyos_ip, key,rule_num, outbound_int, source_address, trans_address)
    return jsonify({'message': 'NAT configuration submitted successfully. Refresh you browser', 'success': True})
    

@app.route('/del_rule', methods=['POST'])
def del_rule():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    rule_num = request.form['rule']
    
    success = retrieve_data.del_rule(vyos_ip, key,rule_num)
    if success:
        return jsonify({'message': 'Rule deleted successfully. Refresh you browser', 'success': True})
    else:
        return jsonify({'message': 'Failed to delete rule. Please check the logs for more information.', 'success': False})
        
    
        

@app.route('/save_config', methods=['POST'])
def save_config():
    vyos_ip = session.get('vyos_ip', None)
    key = session.get('key', None)
    success = retrieve_data.save_configuration(vyos_ip, key)
    if success:
        return jsonify({'message': 'Configuration saved successfully.', 'success': True})
    else:
        return jsonify({'message': 'Failed to save configuration. Please check the logs for more information.', 'success': False})

if __name__ == '__main__':
    app.run(debug=True)
