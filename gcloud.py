import os
import logging
from google.cloud import storage
from datetime import datetime, timedelta
from google.auth import exceptions as auth_exceptions
from flask import Flask, request, jsonify

class CloudStorage:
    def __init__(self):
        try:
            # Get absolute path to service account file
            current_dir = os.path.dirname(os.path.abspath(__file__))
            service_account_path = os.path.join(current_dir, 'service-account.json')
            
            if not os.path.exists(service_account_path):
                raise FileNotFoundError(
                    f"Service account file not found at: {service_account_path}"
                )

            logging.info(f"Using service account from: {service_account_path}")
            
            # Validate service account key format
            try:
                self.client = storage.Client.from_service_account_json(service_account_path)
            except auth_exceptions.DefaultCredentialsError as e:
                logging.error(f"Invalid service account key format: {e}")
                raise
            except auth_exceptions.RefreshError as e:
                logging.error(f"JWT validation failed: {e}")
                raise

            self.bucket_name = "cbms-storage"
            
            # Get or create bucket
            try:
                self.bucket = self.client.get_bucket(self.bucket_name)
                logging.info(f"Connected to existing bucket: {self.bucket_name}")
            except Exception:
                logging.info(f"Creating new bucket: {self.bucket_name}")
                self.bucket = self.client.create_bucket(
                    self.bucket_name,
                    location="asia-south1"
                )
                
        except Exception as e:
            error_msg = f"Failed to initialize Cloud Storage: {str(e)}"
            logging.error(error_msg)
            raise Exception(error_msg)

    def upload_file(self, file_data, storage_path, content_type):
        """Upload a file to Google Cloud Storage"""
        try:
            blob = self.bucket.blob(storage_path)
            blob.upload_from_string(file_data, content_type=content_type)
            return blob.public_url
        except Exception as e:
            logging.error(f"Upload failed: {e}")
            raise

    def download_file(self, storage_path):
        """Download a file from Google Cloud Storage"""
        try:
            blob = self.bucket.blob(storage_path)
            return blob.download_as_bytes()
        except Exception as e:
            logging.error(f"Download failed: {e}")
            raise

    def generate_signed_url(self, storage_path, expiration=3600):
        """Generate a signed URL for temporary access"""
        try:
            blob = self.bucket.blob(storage_path)
            url = blob.generate_signed_url(
                expiration=datetime.utcnow() + timedelta(seconds=expiration),
                method='GET'
            )
            return url
        except Exception as e:
            logging.error(f"URL generation failed: {e}")
            raise

# Test the connection if run directly
if __name__ == "__main__":
    try:
        storage = CloudStorage()
        logging.info(f"Successfully connected to bucket: {storage.bucket_name}")
        logging.info("Available buckets:")
        for bucket in storage.client.list_buckets():
            logging.info(f"- {bucket.name}")
    except Exception as e:
        logging.error(f"Connection test failed: {str(e)}")