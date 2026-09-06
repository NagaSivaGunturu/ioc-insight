import truststore

def initialize_ssl():
    truststore.inject_into_ssl()