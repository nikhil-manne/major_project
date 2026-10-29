"""
MinIO / S3 Object Storage Client
Handles session archive uploads and downloads according to docs/schema.md:
  /sessions/{session_id}/terminal.cast
  /sessions/{session_id}/network.pcap
  /sessions/{session_id}/events.jsonl
  /sessions/{session_id}/manifest.json
"""
import io
import json
import logging
import os
from typing import Any, Dict, List, Optional
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from shared.config import settings

logger = logging.getLogger("cyberrange.s3")


class S3StorageClient:
    def __init__(self):
        self.endpoint_url = f"http://{settings.MINIO_ENDPOINT}" if not settings.MINIO_ENDPOINT.startswith("http") else settings.MINIO_ENDPOINT
        self.bucket = settings.MINIO_BUCKET_SESSIONS
        self.client = None
        self._connected = False
        self._init_client()

    def _init_client(self):
        try:
            self.client = boto3.client(
                "s3",
                endpoint_url=self.endpoint_url,
                aws_access_key_id=settings.MINIO_ROOT_USER,
                aws_secret_access_key=settings.MINIO_ROOT_PASSWORD,
                config=Config(
                    signature_version="s3v4",
                    connect_timeout=1,
                    read_timeout=1,
                    retries={"max_attempts": 1}
                ),
                region_name="us-east-1"
            )
            # Ensure bucket exists
            self._ensure_bucket()
            self._connected = True
            logger.info(f"Connected to MinIO at {self.endpoint_url}, bucket: '{self.bucket}'")
        except Exception as e:
            logger.warning(f"Could not connect to MinIO at {self.endpoint_url}: {e}. Local disk fallback active.")
            self._connected = False

    def _ensure_bucket(self):
        if not self.client:
            return
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except ClientError:
            try:
                self.client.create_bucket(Bucket=self.bucket)
                logger.info(f"Created MinIO bucket '{self.bucket}'")
            except Exception as e:
                logger.debug(f"Bucket creation check: {e}")

    @property
    def is_available(self) -> bool:
        return self._connected and self.client is not None

    def upload_text(self, text_content: str, key: str, content_type: str = "text/plain") -> bool:
        """Uploads string content directly to an S3 object key."""
        if not self.is_available:
            return False
        try:
            data = text_content.encode("utf-8")
            self.client.put_object(
                Bucket=self.bucket,
                Key=key.lstrip("/"),
                Body=data,
                ContentType=content_type
            )
            return True
        except Exception as e:
            logger.error(f"Failed to upload text to s3://{self.bucket}/{key}: {e}")
            return False

    def upload_json(self, data: Dict[str, Any], key: str) -> bool:
        """Uploads JSON-serializable dictionary to S3 key."""
        return self.upload_text(json.dumps(data, indent=2, default=str), key, content_type="application/json")

    def upload_file(self, local_path: str, key: str) -> bool:
        """Uploads a file from local filesystem to S3."""
        if not self.is_available or not os.path.exists(local_path):
            return False
        try:
            self.client.upload_file(local_path, self.bucket, key.lstrip("/"))
            return True
        except Exception as e:
            logger.error(f"Failed to upload file {local_path} to s3://{self.bucket}/{key}: {e}")
            return False

    def get_text(self, key: str) -> Optional[str]:
        """Retrieves object content as text string."""
        if not self.is_available:
            return None
        try:
            resp = self.client.get_object(Bucket=self.bucket, Key=key.lstrip("/"))
            return resp["Body"].read().decode("utf-8")
        except Exception as e:
            logger.debug(f"Could not read s3://{self.bucket}/{key}: {e}")
            return None

    def get_json(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieves and parses JSON object from S3."""
        content = self.get_text(key)
        if content:
            try:
                return json.loads(content)
            except Exception:
                pass
        return None

    def list_keys(self, prefix: str = "") -> List[str]:
        """Lists all keys under a given prefix."""
        if not self.is_available:
            return []
        try:
            resp = self.client.list_objects_v2(Bucket=self.bucket, Prefix=prefix.lstrip("/"))
            items = resp.get("Contents", [])
            return [it["Key"] for it in items]
        except Exception as e:
            logger.error(f"Error listing keys under {prefix}: {e}")
            return []


# Global singleton S3 client
s3_client = S3StorageClient()
