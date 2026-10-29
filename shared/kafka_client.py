"""
Kafka Event Backbone Client
Provides asynchronous / non-blocking producer helpers and consumer base classes
for real event distribution across raw.* and normalized.events topics.
Includes graceful fallback if the Kafka broker is offline during local testing.
"""
import asyncio
import json
import logging
from typing import Any, Callable, Dict, List, Optional

from shared.config import settings

logger = logging.getLogger("cyberrange.kafka")

# Try importing confluent_kafka, fall back gracefully if missing
try:
    from confluent_kafka import Producer, Consumer, KafkaError
    HAS_CONFLUENT = True
except ImportError:
    HAS_CONFLUENT = False
    logger.info("confluent-kafka not installed; running in resilient event channel mode.")


class KafkaProducerHelper:
    def __init__(self, bootstrap_servers: Optional[str] = None):
        self.bootstrap_servers = bootstrap_servers or settings.KAFKA_BOOTSTRAP_SERVERS
        self.producer = None
        self._connected = False
        self._init_producer()

    def _init_producer(self):
        if not HAS_CONFLUENT:
            return
        try:
            conf = {
                "bootstrap.servers": self.bootstrap_servers,
                "client.id": "cyberrange-producer",
                "queue.buffering.max.messages": 100000,
                "message.timeout.ms": 3000,
                "socket.timeout.ms": 2000,
            }
            self.producer = Producer(conf)
            self._connected = True
            logger.info(f"Kafka Producer initialized for {self.bootstrap_servers}")
        except Exception as e:
            logger.warning(f"Could not connect to Kafka broker at {self.bootstrap_servers}: {e}")
            self.producer = None
            self._connected = False

    def produce(self, topic: str, value: Dict[str, Any], key: Optional[str] = None):
        """Publishes a JSON payload to a Kafka topic."""
        payload_bytes = json.dumps(value, default=str).encode("utf-8")
        key_bytes = key.encode("utf-8") if key else None

        if self.producer and self._connected:
            try:
                self.producer.produce(
                    topic=topic,
                    key=key_bytes,
                    value=payload_bytes,
                    callback=self._delivery_report
                )
                self.producer.poll(0)
                return True
            except Exception as e:
                logger.error(f"Error producing message to {topic}: {e}")
                return False
        return False

    def flush(self, timeout: float = 1.0):
        if self.producer and self._connected:
            try:
                self.producer.flush(timeout)
            except Exception:
                pass

    def _delivery_report(self, err, msg):
        if err:
            logger.warning(f"Kafka message delivery failed to {msg.topic()}: {err}")


class KafkaConsumerBase:
    def __init__(self, topics: List[str], group_id: str, bootstrap_servers: Optional[str] = None):
        self.topics = topics
        self.group_id = group_id
        self.bootstrap_servers = bootstrap_servers or settings.KAFKA_BOOTSTRAP_SERVERS
        self.consumer = None
        self.running = False
        self._init_consumer()

    def _init_consumer(self):
        if not HAS_CONFLUENT:
            return
        try:
            conf = {
                "bootstrap.servers": self.bootstrap_servers,
                "group.id": self.group_id,
                "auto.offset.reset": "latest",
                "enable.auto.commit": True,
                "socket.timeout.ms": 2000,
            }
            self.consumer = Consumer(conf)
            self.consumer.subscribe(self.topics)
            logger.info(f"Kafka Consumer subscribed to {self.topics} in group {self.group_id}")
        except Exception as e:
            logger.warning(f"Could not initialize Kafka consumer: {e}")
            self.consumer = None

    def poll_message(self, timeout: float = 0.5) -> Optional[Dict[str, Any]]:
        """Polls for a single message from subscribed topics."""
        if not self.consumer:
            return None
        try:
            msg = self.consumer.poll(timeout)
            if msg is None:
                return None
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    logger.warning(f"Kafka consumer error: {msg.error()}")
                return None
            val = json.loads(msg.value().decode("utf-8"))
            return val
        except Exception as e:
            logger.debug(f"Kafka poll exception: {e}")
            return None

    def close(self):
        if self.consumer:
            try:
                self.consumer.close()
            except Exception:
                pass


# Global singleton producer
kafka_producer = KafkaProducerHelper()
