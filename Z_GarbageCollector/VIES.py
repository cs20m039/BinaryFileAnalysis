import requests
import logging

# Setup basic logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')

def query_vat_number(country_code, vat_number):
    url = 'https://ec.europa.eu/taxation_customs/vies/rest-api/check-vat-number'  # Example URL
    params = {
        'countryCode': country_code,
        'vatNumber': vat_number
    }

    try:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            logging.info("Success: %s", data)
            print("Company Name:", data.get("companyName"))
            print("Address:", data.get("address"))
        else:
            logging.error("Failed to retrieve data. Status code: %s, Response: %s", response.status_code, response.text)
            print("Failed to retrieve data. See app.log for details.")
    except requests.exceptions.RequestException as e:
        logging.exception("Request failed: %s", e)
        print("An error occurred. See app.log for details.")

# Example usage
query_vat_number('BE', '0849510162')
