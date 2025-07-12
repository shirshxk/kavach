import logging

class Logger:
    def __init__(self, log_file="firewall.log"):
        self.logger = logging.getLogger("FirewallLogger")
        self.logger.setLevel(logging.INFO)
        file_handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def log(self, message, level="INFO"):
        if level == "INFO":
            self.logger.info(message)
        elif level == "WARNING":
            self.logger.warning(message)
        elif level == "ERROR":
            self.logger.error(message)

# Example usage
if __name__ == "__main__":
    logger = Logger()
    logger.log("Firewall started", level="INFO")
