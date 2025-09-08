import requests
import json

def test_fastmcp_server():
   base_url = "http://localhost:4444/mcp"
   headers = {
       'accept': 'application/json, text/event-stream',
       'content-type': 'application/json',
       'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzU3NDkzMTA2fQ.N2A-fMqsUUmpM4VTmlWxL85-QyBr5udMhHOxAQs1HjU',
       'X-Tenant-Id': 'tokens'
   }
   
   print("check 1")
   
   init_payload = {
       "jsonrpc": "2.0",
       "method": "initialize",
       "params": {
           "protocolVersion": "2024-11-05",
           "capabilities": {},
           "clientInfo": {
               "name": "python-client",
               "version": "1.0.0"
           }
       },
       "id": 1
   }
   
   response = requests.post(base_url, headers=headers, json=init_payload)
   session_id = response.json().get('id')
   print(f"Session ID: {response.json()} {session_id}")
   
   if not session_id:
       print("No session ID received")
       return
   
   headers['Mcp-Session-Id'] = str(session_id)
   
   init_complete_payload = {
       "jsonrpc": "2.0",
       "method": "notifications/initialized"
   }
   
   requests.post(base_url, headers=headers, json=init_complete_payload)
   print("Initialization complete")
   
   add_payload = {
       "jsonrpc": "2.0",
       "method": "tools/call",
       "params": {
           "name": "echo-echo",
           "arguments": {
               "message": "hi-est"
           }
       },
       "id": 2
   }
   
   response = requests.post(base_url, headers=headers, json=add_payload)
   
   lines = response.text.split('\n')
   data_line = next((line for line in lines if line.startswith('data: ')), None)
   
   if data_line:
       json_data = data_line[6:]
       result = json.loads(json_data)
       answer = result['result']['structuredContent']['result']
       print(f"Add result: {answer}")
   else:
       print("No data found in response")
       print("Raw response:", response.text)
   
   hello_payload = {
       "jsonrpc": "2.0",
       "method": "tools/call",
       "params": {
           "name": "hello",
           "arguments": {}
       },
       "id": 3
   }
   
   response = requests.post(base_url, headers=headers, json=hello_payload)
   lines = response.text.split('\n')
   data_line = next((line for line in lines if line.startswith('data: ')), None)
   
   if data_line:
       json_data = data_line[6:]
       result = json.loads(json_data)
       hello_response = result['result']['content'][0]['text']
       print(f"Hello response: {hello_response}")
   
   print("Test complete")

if __name__ == "__main__":
   try:
       test_fastmcp_server()
   except requests.exceptions.ConnectionError:
       print("Check MCP its not working on 8000")
   except Exception as e:
       print(f"Error: {e}")
