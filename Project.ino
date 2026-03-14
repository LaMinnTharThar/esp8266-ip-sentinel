#include <ESP8266WiFi.h>
#include <user_interface.h>
#include <ESP8266WebServer.h>

// ---------------- AP SETTINGS ----------------
const char* apSSID = "ESP8266_AP";
const char* apPassword = "12345678";

// ---------------- ADMIN ----------------
const char* adminUser = "admin";
const char* adminPass = "1234";
bool loggedIn = false;

// ---------------- PINS ----------------
const int greenPin = D1;
const int redPin   = D3;
const int buzzerPin= D2;

// ---------------- SERVER ----------------
ESP8266WebServer server(80);

// ---------------- DEVICE STRUCT ----------------
struct DeviceInfo {
  String mac;
  String ip;
  String status;
  unsigned long firstSeenMillis; // for running timer
  bool removed;                  // logical removal flag
};

DeviceInfo devices[20];
int deviceCount = 0;

// ---------------- AUTHORIZED LIST ----------------
String authorizedMACs[20] = {
  "50:2E:91:18:CE:58" // example authorized
};
int authorizedCount = 1;

// ---------------- UTILITIES ----------------
String macToString(uint8_t* mac) {
  char buf[18];
  sprintf(buf,"%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0],mac[1],mac[2],
          mac[3],mac[4],mac[5]);
  return String(buf);
}

bool isAuthorized(String mac){
  for(int i=0;i<authorizedCount;i++){
    if(mac.equalsIgnoreCase(authorizedMACs[i]))
      return true;
  }
  return false;
}

// Format elapsed time to HH:MM:SS
String formatTime(unsigned long ms){
  unsigned long sec = ms / 1000;
  unsigned long hr = sec / 3600;
  unsigned long min = (sec % 3600) / 60;
  sec = sec % 60;
  char buf[9];
  sprintf(buf,"%02lu:%02lu:%02lu", hr, min, sec);
  return String(buf);
}

// ---------------- SCAN DEVICES ----------------
void scanDevices(){
  struct station_info* stat_info = wifi_softap_get_station_info();
  bool anyUnauthorized = false;

  // Mark all devices as not found in this scan
  bool foundFlags[20] = {false};

  // Scan currently connected stations
  while(stat_info != NULL){
    String mac = macToString(stat_info->bssid);
    IPAddress ip(stat_info->ip.addr);
    String ipStr = ip.toString();
    bool auth = isAuthorized(mac);

    bool found = false;
    for(int i=0;i<deviceCount;i++){
      if(devices[i].mac == mac){
        if(!devices[i].removed){ // only update if not removed
          devices[i].status = auth ? "AUTHORIZED" : "UNAUTHORIZED";
        }
        found = true;
        foundFlags[i] = true; // mark device as still connected
        break;
      }
    }

    // New device
    if(!found && deviceCount < 20){
      devices[deviceCount].mac = mac;
      devices[deviceCount].ip = ipStr;
      devices[deviceCount].status = auth ? "AUTHORIZED" : "UNAUTHORIZED";
      devices[deviceCount].firstSeenMillis = millis();
      devices[deviceCount].removed = false;
      foundFlags[deviceCount] = true;
      deviceCount++;
    }

    if(!auth) anyUnauthorized = true;
    stat_info = STAILQ_NEXT(stat_info,next);
  }

  wifi_softap_free_station_info();

  // Remove devices that disconnected
  for(int i=0;i<deviceCount;i++){
    if(!foundFlags[i]){
      devices[i].removed = true;
    }
  }

  // Update LEDs & Buzzer
  bool activeUnauthorized = false;
  for(int i=0;i<deviceCount;i++){
    if(!devices[i].removed && devices[i].status=="UNAUTHORIZED"){
      activeUnauthorized = true;
      break;
    }
  }
  digitalWrite(redPin, activeUnauthorized);
  digitalWrite(greenPin, !activeUnauthorized);
  digitalWrite(buzzerPin, activeUnauthorized ? HIGH : LOW);
}

// ---------------- LOGIN ----------------
void handleLogin(){
  if(server.method()==HTTP_POST){
    if(server.arg("u")==adminUser && server.arg("p")==adminPass){
      loggedIn=true;
      server.sendHeader("Location","/dashboard");
      server.send(303);
      return;
    }
  }

  String html = "<!DOCTYPE html><html><head><meta charset='utf-8'>";
  html += "<title>IP Sentinel Admin Authentication</title>";
  html += "<style>"
          "body{background:#121212;color:#eee;font-family:Segoe UI;display:flex;justify-content:center;align-items:center;height:100vh;}"
          "form{background:#1e1e1e;padding:30px;border-radius:10px;text-align:center;}"
          "input{margin:10px;padding:10px;width:200px;border-radius:5px;border:none;}"
          "button{padding:10px 20px;border:none;border-radius:5px;background:#00ff88;color:#000;font-weight:bold;cursor:pointer;}"
          "</style></head><body>";
  html += "<form method='POST'>"
          "<h2>IP Sentinel Admin Authentication</h2>"
          "Username:<br><input name='u'><br>"
          "Password:<br><input type='password' name='p'><br>"
          "<button>Login</button></form></body></html>";

  server.send(200,"text/html",html);
}

// ---------------- DASHBOARD ----------------
void handleDashboard(){
  if(!loggedIn){
    server.sendHeader("Location","/");
    server.send(303);
    return;
  }

  String html = "<!DOCTYPE html><html><head><meta charset='utf-8'>";
  html += "<title>IP Sentinel Monitor</title>";
  html += "<meta http-equiv='refresh' content='2'>"; // auto-refresh every 2s
  html += "<style>"
          "body{background:#121212;color:#eee;font-family:Segoe UI;padding:20px}"
          "h2{text-align:center;}"
          ".card{background:#1e1e1e;padding:15px;border-radius:10px;margin-bottom:15px;}"
          "table{width:100%;border-collapse:collapse}"
          "th,td{padding:10px;border-bottom:1px solid #333;text-align:center}"
          ".auth{color:#00ff88;font-weight:bold}"
          ".unauth{color:#ff4444;font-weight:bold}"
          "button{padding:5px 10px;border:none;border-radius:5px;cursor:pointer;margin:2px}"
          "</style></head><body>";

  html += "<h2>IP Sentinel Monitor</h2>";
  html += "<div class='card'><table><thead><tr><th>MAC</th><th>IP</th><th>Status</th><th>Action</th><th>Connected Time</th></tr></thead><tbody>";

  unsigned long nowMillis = millis();

  for(int i=0;i<deviceCount;i++){
    if(devices[i].removed) continue; // skip removed or disconnected devices
    html += "<tr>";
    html += "<td>"+devices[i].mac+"</td>";
    html += "<td>"+devices[i].ip+"</td>";
    if(devices[i].status=="AUTHORIZED"){
      html += "<td class='auth'>AUTHORIZED</td><td></td>";
    }else{
      html += "<td class='unauth'>UNAUTHORIZED</td>";
      html += "<td><button onclick=\"authorize('"+devices[i].mac+"')\">Authorize</button>"
              "<button onclick=\"remove('"+devices[i].mac+"')\">Remove</button></td>";
    }
    html += "<td>"+formatTime(nowMillis - devices[i].firstSeenMillis)+"</td>";
    html += "</tr>";
  }

  html += "</tbody></table></div>";

  html += "<script>"
          "async function authorize(m){"
          "await fetch('/authorize',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+m});"
          "window.location.reload();}"
          "async function remove(m){"
          "await fetch('/deauthorize',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'mac='+m});"
          "window.location.reload();}"
          "</script>";

  html += "</body></html>";
  server.send(200,"text/html",html);
}

// ---------------- AUTHORIZE ----------------
void handleAuthorize(){
  String mac = server.arg("mac");
  if(authorizedCount<20){
    authorizedMACs[authorizedCount++] = mac;
    for(int i=0;i<deviceCount;i++){
      if(devices[i].mac==mac){
        devices[i].status="AUTHORIZED";
        devices[i].removed=false;
      }
    }
  }
  server.send(200,"text/plain","OK");
}

// ---------------- REMOVE (kick) ----------------
void handleDeauthorize(){
  String mac = server.arg("mac");
  for(int i=0;i<deviceCount;i++){
    if(devices[i].mac==mac){
      devices[i].removed=true; // remove from table immediately
    }
  }
  scanDevices(); // update LEDs and buzzer
  server.send(200,"text/plain","OK");
}

// ---------------- SETUP ----------------
void setup(){
  Serial.begin(115200);
  pinMode(greenPin,OUTPUT);
  pinMode(redPin,OUTPUT);
  pinMode(buzzerPin,OUTPUT);

  WiFi.mode(WIFI_AP);
  WiFi.softAP(apSSID,apPassword);

  Serial.println("===================================");
  Serial.print(" Connect to SSID: "); Serial.println(apSSID);
  Serial.print(" Use this IP in your browser: "); Serial.println(WiFi.softAPIP());
  Serial.println("===================================");

  server.on("/",handleLogin);
  server.on("/dashboard",handleDashboard);
  server.on("/authorize",HTTP_POST,handleAuthorize);
  server.on("/deauthorize",HTTP_POST,handleDeauthorize);

  server.begin();
}

// ---------------- LOOP ----------------
void loop(){
  server.handleClient();
  scanDevices();
}
