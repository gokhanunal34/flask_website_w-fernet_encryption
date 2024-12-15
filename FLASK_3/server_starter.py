""" Start with running this script to initiate
    the socket and handle the decoding """

from BakingContestPeopleCreateDB import cipher
import socketserver
import sqlite3
import logging
import hmac
import hashlib

# logging.debug activated
logging.basicConfig(level=logging.DEBUG)

# Load the HMAC key from .key file
with open('hmac_key.key', 'rb') as key_file:
    hmac_key = key_file.read()


def decrypt_m(data: bytes, hmac_key: bytes) -> str:
    """ Decrypt the incoming message & return the decrypted message. """
    try:
        # get the HMAC & encrypted message
        hmac_size:int = hashlib.sha3_512().digest_size
        received_hmac: int|bytes = data[:hmac_size]
        encrypted_message: int|bytes = data[hmac_size:]

        # Verify the HMAC
        calculated_hmac:bytes = hmac.new(hmac_key, encrypted_message, hashlib.sha3_512).digest()
        # if the message is not authenticated, flash an error
        if not hmac.compare_digest(received_hmac, calculated_hmac):
            # I was able to replicate this error successfully
            logging.error("Unauthenticated Delete Baking Contest Entry message received! Be on alert! Watch out for bad guys!!!")
            return 'failure'

        # Decrypt the message
        decrypted_message = cipher.decrypt(encrypted_message).decode()
        logging.info(f"Decrypted message: {decrypted_message}")

        # Assuming the message contains only the entry_id
        entry_id = decrypted_message

        # Input validation
        if not entry_id.isdigit() or int(entry_id) <= 0:
            logging.error(f"Input validation failed: EntryId must be greater than 0. Received: {entry_id}")
            return 'failure'

        # Establish the sqlite3 connection and get the cursor
        con = sqlite3.connect('baking_contest.db')
        cursor = con.cursor()
        # Check for the entry in the BakingContestEntry table
        cursor.execute('SELECT 1 FROM BakingContestEntry WHERE EntryID = ?', (entry_id,))
        if cursor.fetchone() is None:
            logging.error(f"Input validation failed: EntryId does not exist in the database. Received: {entry_id}")
            con.close()
            return 'failure'

        # Delete the entry in the database
        cursor.execute('DELETE FROM BakingContestEntry WHERE EntryID = ?', (entry_id,))
        con.commit()
        con.close()
        logging.info(f"Record successfully deleted for EntryID: {entry_id}")
        return 'success'
    except Exception as e:
        logging.error(f"Error handling request: {e}")
        return 'failure'


class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        """ Handle incoming connection with MyTCPHandler per instructions """
        data = self.request.recv(1024).strip()
        logging.info(f"Data received: {data}")

        # decrypt the message and save it to result
        result = decrypt_m(data, hmac_key)
        # post the result
        self.request.sendall(result.encode())


def start_socket_server():
    """ Start the appropriate socket server given in the instructions """
    logging.info("Initializing socket server...")
    try:
        HOST, PORT = "localhost", 8888  # per instructions
        with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
            logging.info(f"Socket Server started and listening on port {PORT}")
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                server.shutdown()
                logging.info("Server shut down successfully!")
    except Exception as e:
        logging.error(f"Error starting socket server: {e}")

# Name block
if __name__ == '__main__':
    start_socket_server()
