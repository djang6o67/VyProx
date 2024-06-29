import requests


# Replace <vyos-router-ip> with the actual IP address of your VyOS router
VYOS_API_URL = "https://192.168.0.121/configure"
payload={'data': '{"op": "set", "path": ["interfaces", "ethernet", "eth1", "address", "192.168.0.140"]}',
         'key': 'theKey'
        }
headers = {}
def test_vyos_api():
    try:
        response = requests.request("POST",VYOS_API_URL,headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            print("VyOS API is working!")
            print("Response:")
            print(response.text)
        else:
            print("Failed to access VyOS API. Status code:", response.status_code)
    except Exception as e:
        print("An error occurred:", e)

if __name__ == "__main__":
    test_vyos_api()


# import retrieve_data as retrieve_data

# retrieve_data.save_config()

vyos_api_url = "https://192.168.0.121/"

def configure_interface():
    url = vyos_api_url + "retrieve"
    payload = {
        'data': '{"op": "showConfig", "path": []}',
        'key': 'theKey'
    }
    headers = {}
    try:
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        if response.status_code == 200:
            return print(response.text)
        else:
            print("Failed to configure interface. Status code:", response.status_code)
            return print(response.text)
    except Exception as e:
        print("An error occurred while configuring interface:", e)
        return False
    
configure_interface()




