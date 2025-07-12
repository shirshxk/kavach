class ConnectionTracker:
    def __init__(self):
        self.connections = {}

    def add_connection(self, src_ip, dest_ip, protocol):
        conn_id = f"{src_ip}:{dest_ip}:{protocol}"
        self.connections[conn_id] = {"status": "active"}
        print(f"Added connection: {conn_id}")

    def remove_connection(self, src_ip, dest_ip, protocol):
        conn_id = f"{src_ip}:{dest_ip}:{protocol}"
        if conn_id in self.connections:
            del self.connections[conn_id]
            print(f"Removed connection: {conn_id}")
        else:
            print("Connection not found.")

    def is_connection_active(self, src_ip, dest_ip, protocol):
        conn_id = f"{src_ip}:{dest_ip}:{protocol}"
        return conn_id in self.connections

    def get_active_connections(self):
        """
        Returns a list of all active connections.
        """
        return [f"{conn_id} - {details['status']}" for conn_id, details in self.connections.items()]
