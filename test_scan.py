import requests

url = "http://127.0.0.1:5000/scan"  # Your Flask API endpoint
data = {"url": "https://example.com"}  # The target website to scan

response = requests.post(url, json=data)  # Send the request
print(response.json())  # Print the response
