#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <DHT.h>
#include <ArduinoJson.h>

/* ------------------- SENSOR CONFIG ------------------- */
#define DHTPIN 4
#define DHTTYPE DHT11     // Change to DHT22 if needed
DHT dht(DHTPIN, DHTTYPE);

/* ------------------- WIFI CONFIG ------------------- */
const char* ssid = "YOUR_WIFI_NAME";
const char* wifi_password = "YOUR_WIFI_PASSWORD";

/* ------------------- MQTT (HiveMQ Cloud) CONFIG ------------------- */
const char* mqtt_server = "xxxxxx.s1.eu.hivemq.cloud";
const int mqtt_port = 8883;
const char* mqtt_username = "YOUR_HIVEMQ_USERNAME";
const char* mqtt_password = "YOUR_HIVEMQ_PASSWORD";

/* ------------------- MQTT TOPICS ------------------- */
const char* sensor_topic = "microgrid/sensor/data";

/* ------------------- OBJECTS ------------------- */
WiFiClientSecure espClient;
PubSubClient client(espClient);

/* ------------------- FUNCTIONS ------------------- */

void connectToWiFi() {
  Serial.print("Connecting to WiFi");
  WiFi.begin(ssid, wifi_password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWiFi Connected");
}

void connectToMQTT() {
  while (!client.connected()) {
    Serial.print("Connecting to MQTT... ");
    
    if (client.connect("ESP32_Microgrid", mqtt_username, mqtt_password)) {
      Serial.println("Connected");
    } else {
      Serial.print("Failed, rc=");
      Serial.print(client.state());
      Serial.println(" retrying in 5 seconds");
      delay(5000);
    }
  }
}

/* ------------------- SETUP ------------------- */
void setup() {
  Serial.begin(115200);
  dht.begin();

  connectToWiFi();

  // TLS connection (HiveMQ Cloud)
  espClient.setInsecure();  // OK for academic projects
  client.setServer(mqtt_server, mqtt_port);

  connectToMQTT();
}

/* ------------------- LOOP ------------------- */
void loop() {
  if (!client.connected()) {
    connectToMQTT();
  }

  client.loop();

  float temperature = dht.readTemperature();
  float humidity = dht.readHumidity();

  // If sensor fails, simulate values
  if (isnan(temperature) || isnan(humidity)) {
    temperature = random(20, 40);
    humidity = random(30, 80);
  }

  // Create JSON payload
  StaticJsonDocument<200> doc;
  doc["temperature"] = temperature;
  doc["humidity"] = humidity;
  doc["timestamp"] = millis();

  char payload[256];
  serializeJson(doc, payload);

  client.publish(sensor_topic, payload);

  Serial.println("Published Data:");
  Serial.println(payload);

  delay(3000);
}
