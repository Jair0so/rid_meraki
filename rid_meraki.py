import os
import requests
from rich.console import Console
from rich import pretty
from rich.prompt import Prompt
from rich.table import Table
import yaml
import json

class MerakiManager:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = 'https://api.meraki.com/api/v1'
        self.headers = {
            'X-Cisco-Meraki-API-Key': self.api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    def get_organizations(self):
        response = requests.get(f'{self.base_url}/organizations', headers=self.headers)
        return response.json()

    def get_networks(self, org_id):
        response = requests.get(f"{self.base_url}/organizations/{org_id}/networks", headers=self.headers)
        return response.json()

    def get_devices(self, org_id):
        response = requests.get(f'{self.base_url}/organizations/{org_id}/inventoryDevices', headers=self.headers)
        return response.json()

class MerakiActions(MerakiManager):
    def __init__(self, api_key):
        super().__init__(api_key)
        self.console = Console()

    def select_organization(self):
        orgs = self.get_organizations()
        org_table = Table(title="Organizations")
        org_table.add_column("ID", style="cyan")
        org_table.add_column("Name", style="magenta")

        for org in orgs:
            org_table.add_row(str(org['id']), org['name'])

        self.console.print(org_table)
        org_id = Prompt.ask("Enter the ID of the organization")
        return org_id
    
    def select_network(self, org_id):
        networks = self.get_networks(org_id)
        network_table = Table(title="Networks")
        network_table.add_column("ID", style="cyan")
        network_table.add_column("Name", style="magenta")

        for network in networks:
            network_table.add_row(str(network['id']), network['name'])

        self.console.print(network_table)
        network_id = Prompt.ask("Enter the network ID you want to add the vlans")
        return network_id

    def show_menu(self):
        self.console.print("[bold magenta]Select an option:[/bold magenta]")
        self.console.print("[green]1.[/green] Provide all devices in the network")
        self.console.print("[green]2.[/green] Provide all access points")
        self.console.print("[green]3.[/green] Create a new network")
        self.console.print("[green]4.[/green] Bind hardware to a network")
        self.console.print("[green]5.[/green] Default site creation")
        self.console.print("[green]6.[/green] Vlan creation")
        choice = Prompt.ask("[bold cyan]Enter your choice[/bold cyan]", choices=["1", "2", "3", "4", "5", "6"])
        return choice

    def execute_action(self, org_id, choice):
        if choice == '1' or choice == '2' or choice == '6':
            devices = self.get_devices(org_id)
            if choice == '1':
                for device in devices:
                    self.console.print(f"[cyan]{device['model']}[/cyan] - [magenta]{device['serial']}[/magenta]")
            elif choice == '2':
                for device in devices:
                    if device['model'].startswith('MR'):
                        self.console.print(f"[cyan]{device['model']}[/cyan] - [magenta]{device['serial']}[/magenta]")
            elif choice == '6':
                network_id = self.select_network(org_id)
                self.configure_vlans(network_id)
                
                

        elif choice == '3':
            self.create_network(org_id)
        elif choice == '4':
            self.bind_hardware_to_network(org_id)
        elif choice == '5':
            self.create_network(org_id)
            self.bind_hardware_to_network(org_id)
        
            

    def create_network(self, org_id):
        self.console.print("\n[bold]Creating a new network...[/bold]")
        name = self.console.input("[bold cyan]Enter network name: [/bold cyan]")
        product_types_input = self.console.input("[bold cyan]Enter network product types (e.g., appliance, switch, wireless) separated by commas: [/bold cyan]")
        product_types = [ptype.strip() for ptype in product_types_input.split(",")]  # Convert to list and strip spaces
        tags_input = self.console.input("[bold cyan]Enter tags separated by commas (leave blank if none): [/bold cyan]")
        tags = [tag.strip() for tag in tags_input.split(",")] if tags_input else []  # Create list of tags or empty list if input is blank
    

        payload = {
            "name": name,
            "productTypes": product_types,
            "timeZone": "America/New_York",  # Example timezone, adjust as needed
            "tags": tags,
        }

        response = requests.post(
            f"{self.base_url}/organizations/{org_id}/networks",
            headers=self.headers,
            json=payload
        )

        if response.status_code == 201:
            self.console.print("[bold green]Network created successfully![/bold green]")
            self.console.print(response.json())
        else:
            self.console.print(f"[bold red]Failed to create network. Status code: {response.status_code}[/bold red]")
            self.console.print(f"[bold red]Response: {response.text}[/bold red]")
    
    def bind_hardware_to_network(self, ):
        orgs = self.get_organizations()
        if not orgs:
            self.console.print("[bold red]No organizations found.[/bold red]")
            return

        # For simplicity, using the first organization. You might want to allow the user to select one.
        org_id = orgs[0]['id']
        networks = self.get_networks(org_id)
        devices = self.get_devices(org_id)

        self.console.print("[bold]Available Devices:[/bold]")
        for device in devices:
            self.console.print(f"[cyan]Model: {device['model']} - Serial: {device['serial']}[/cyan]")

        serial = self.console.input("[bold cyan]Enter the serial number of the device to add: [/bold cyan]")
        network_id = self.console.input("[bold cyan]Enter the network ID to which the device should be added: [/bold cyan]")

        self.add_device_to_network(network_id, serial)

    def get_networks(self, org_id):
        """Fetches the list of networks for a given organization."""
        response = requests.get(f"{self.base_url}/organizations/{org_id}/networks", headers=self.headers)
        return response.json()

    def add_device_to_network(self, network_id, serial):
        """Adds a device to a specific network."""
        url = f"{self.base_url}/networks/{network_id}/devices/claim"
        payload = {"serial": serial}
        response = requests.post(url, headers=self.headers, json=payload)

        if response.status_code == 200:
            self.console.print("[bold green]Device added successfully to the network![/bold green]")
        else:
            self.console.print(f"[bold red]Failed to add device. Status code: {response.status_code}[/bold red]")
            self.console.print(f"[bold red]Response: {response.text}[/bold red]")
    
    def configure_vlans(self, network_id):
    # Load configurations from YAML file
        with open('inventory.yaml', 'r') as file:
            config = yaml.safe_load(file)['configurations']

        self.console.print(f"\n[bold]Configuring VLANs for network {network_id}...[/bold]")

        # Create a table to display VLAN configuration results
        vlan_table = Table(title="VLAN Configuration Results")
        vlan_table.add_column("VLAN ID", justify="center", style="cyan")
        vlan_table.add_column("Name", justify="center", style="magenta")
        vlan_table.add_column("Subnet", justify="center", style="green")
        vlan_table.add_column("Appliance IP", justify="center", style="red")
        vlan_table.add_column("Status", justify="center", style="blue")

        for vlan in config.get('vlans', []):
            self.console.print(f"Configuring VLAN {vlan['id']}...")
            payload = {
                'id': vlan['id'],
                'name': vlan['name'],
                'subnet': vlan['subnet'],
                'applianceIp': vlan['applianceIp'],
                'groupPolicyId': vlan['groupPolicyId'],
                'templateVlanType': vlan['templateVlanType'],
                'cidr': vlan['cidr'],
                'mask': vlan['mask'],
                #'ipv6': {
                #    'enabled': False
                #}
                #'mandatoryDhcp': { 'enabled': True }
            }
            # imprimimos la informacion para que ver que tenemos la info correcta
            #self.console.print(payload)
            #
            # hacemos el post con la configuracion de las vlans
            #
            self.console.print("\n")

            response = requests.post(
                f"{self.base_url}/networks/{network_id}/appliance/vlans",
                headers=self.headers,
                json=payload
            )
            if response.status_code == 201:
                self.console.print(f"[bold green]VLAN {vlan['id']} configured successfully![/bold green]")
                vlan_table.add_row(
                    str(vlan['id']),
                    vlan['name'],
                    vlan['subnet'],
                    vlan['applianceIp'],
                    "OK",
                )
                # Print the table after configuring all VLANs
                self.console.print(vlan_table)
            else:
                self.console.print(f"[bold red]Failed to configure VLAN {vlan['id']}. Status code: {response.status_code}[/bold red]")
                #self.console.print(f"Response: {response.text}")
                # Add a row to the table for each VLAN configuration attempt
                vlan_table.add_row(
                    str(vlan['id']),
                    vlan['name'],
                    vlan['subnet'],
                    vlan['applianceIp'],
                    'FAILED'
                )
                # Print the table after configuring all VLANs
                self.console.print(vlan_table)

    def configure_multiple_vlans(self, network_id):
        self.console.print(f"\n[bold]Validating if {network_id} is set for multiple vlans...[/bold]")    

        getter = requests.get(
                f"{self.base_url}/networks/{network_id}/appliance/vlans/settings",
                headers=self.headers,
            )
        self.console.print(getter)

        


def main():
    api_key = os.getenv('MERAKI_DASHBOARD_API_KEY')
    if not api_key:
        print("MERAKI_DASHBOARD_API_KEY environment variable is not set.")
        return

    meraki_actions = MerakiActions(api_key)
    org_id = meraki_actions.select_organization()  # Ensure org_id is captured from the selection
    choice = meraki_actions.show_menu()
    meraki_actions.execute_action(org_id, choice)  # Pass both org_id and choice to execute_action

if __name__ == "__main__":
    main()
