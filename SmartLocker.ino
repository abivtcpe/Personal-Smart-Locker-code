

#include <Arduino.h>
#include <avr/sleep.h>
#include <avr/wdt.h>




enum Feedback { FEEDBACK_NONE, FEEDBACK_OK, FEEDBACK_WRONG, FEEDBACK_LOW,
                FEEDBACK_CHANGED, FEEDBACK_BLOCKED, FEEDBACK_FAULT,
                FEEDBACK_WAKE };
#ifndef ENABLE_BATTERY_MONITOR
#define ENABLE_BATTERY_MONITOR 1
#endif
#ifndef HAS_SERVO_POWER_SWITCH
#define HAS_SERVO_POWER_SWITCH 0
#endif
#ifndef ENABLE_DEEP_SLEEP
#define ENABLE_DEEP_SLEEP 1
#endif
#ifndef ENABLE_LEDS
#define ENABLE_LEDS 1
#endif
#ifndef ENABLE_BUZZER
#define ENABLE_BUZZER 1
#endif
#ifndef ENABLE_SERIAL
#define ENABLE_SERIAL 0
#endif
//HAS_SERVO_POWER_SWITCH stays at 0 while the servo has no power switch.
#ifndef ENABLE_BENCH_COMMANDS
#define ENABLE_BENCH_COMMANDS 0
#endif


// 0: hold keypad # about 1.5 seconds for watchdog wake in Power-down.
// 1: use a dedicated D2 button and no watchdog polling.
#ifndef DEDICATED_WAKE_BUTTON
#define DEDICATED_WAKE_BUTTON 0
#endif




const byte redLedPin=4;         //pin 6, resistor and LED to GND
const byte greenLedPin=5;       //pin 11, resistor and LED to GND
const byte buzzerPin=3;         //pin 5, passive piezo only
const byte servoPowerPin=7;     //pin 13, PMOS gate: HIGH = OFF
const byte wakeButtonPin=2;     //pin 4, optional button to GND
const byte batteryPin=A3;       //pin 26
const float ADC_REFERENCE_V=5.0; 
const float BATTERY_TOP_OHM=1000000.0;
const float BATTERY_BOTTOM_OHM=470000.0;
const float LOW_BATTERY_V=6.5;   // Starting value
const float BATTERY_CLEAR_V=6.8;
const unsigned long BATTERY_INTERVAL_MS=60000;
const unsigned long IDLE_TIMEOUT_MS=30000;






// Function declarations for Arduino IDE
struct ShaState;
static void wipeBytes(void *p, uint16_t n);
static uint32_t rotateRight(uint32_t x, uint8_t n);
static void shaInit(ShaState &s);
static void shaBlock(ShaState &s);
static void shaAdd(ShaState &s,const uint8_t *data,uint16_t n);
static void shaFinish(ShaState &s,uint8_t out[32]);
static void sha256(const uint8_t *data,uint16_t n,uint8_t out[32]);
static void hmac256(const uint8_t *key,uint8_t keyLen,
                    const uint8_t *data,uint16_t n,uint8_t out[32]);
static void pinFingerprint(const char *pin,uint8_t n,const uint8_t salt[16],
                           uint16_t rounds,uint8_t out[32]);
static void pinHash(const char *pin,uint8_t n,const uint8_t addedValue[16],
                    uint8_t out[32]);
static bool equalBytes(const uint8_t *a,const uint8_t *b,uint8_t n);
static uint16_t recordCRC(const uint8_t *p,uint8_t n);
static uint32_t recordSequence(const uint8_t *r);
static uint16_t recordRounds(const uint8_t *r);
static bool validRecord(const uint8_t *r);
static void readRecord(int address,uint8_t *r);
static void eraseRecord(int address);
static void eraseLegacyPIN();
static bool storePIN(const char *pin,uint8_t n);
static bool verifyPIN(const char *pin,uint8_t n);
static bool loadSecurePIN();
void stopBuzzer();
void startBuzzer(uint16_t frequency);
void showFeedback(Feedback event);
void allFeedbackOff();
void serviceFeedback();
void setupFeedback();
void turnServoOff();
void turnServoOn();
void checkBattery();
void setupServoPower();
void clearPINBuffers();
void motionFeedback(byte result);
void noteActivity();
void printMotionResult();
void startCurrentLogging();
void resetCurrentWindow();
void applyStableState();
void startServoMove(int requestedPulseUs, bool makeRoundTrip);
void setServoPulse(int pulseWidthMicroseconds);
void servoLocked();
void servoUnlocked();
void setupServoTimer1();
void serviceServoRamp();
void beginServoReturn(byte reason);
void finishServoMove(int completedPulseUs, byte result);
void latchServoFault();
void serviceServoMotion();
void startTimedServoTest();
void readAndLogServoCurrent();
void writeEEPROM(int address, byte data);
byte readEEPROM(int address);
void loadPassword();
int readSmoothADC();
char getKeyFromADC(int adcValue);
char readKeypad(bool wakeOnly);
void clearEnteredPassword();
void runStateMachine(char key);
void disableWatchdog();
void watchdogOneSecond();
void sleepCpuOnce();
void sleepPowerDownOnce();
void leaveIdlePowerSaving();
void enterIdlePowerSaving();
bool serviceIdlePowerSaving();
void checkIdleTimeout();
void checkSerialServoTest();
void setup();
void loop();
#if !ENABLE_SERIAL
struct QuietSerial {
  void begin(unsigned long) {}
  void flush() {}
  int available() {return 0;}
  int read() {return -1;}
  int availableForWrite() {return 0;}
  template<typename T> void print(T) {}
  template<typename T> void println(T) {}
  template<typename T> void print(T,int) {}
  template<typename T> void println(T,int) {}
  void println() {}
};
QuietSerial quietSerial;
#define Serial quietSerial
#endif


//SHA-256
//EEPROM storage
#include <stdint.h>
#include <string.h>
#ifdef __AVR__
#include <avr/pgmspace.h>
#else
#define PROGMEM
#define pgm_read_dword(p) (*(const uint32_t *)(p))
#define pgm_read_byte(p) (*(const uint8_t *)(p))
#endif


//SHA-256 protects new PIN records. HMAC/PBKDF2 saved for old records.
// No downloaded crypto library.
// Algorithm references: FIPS 180-4 and RFC 8018, section 5.2.
static void wipeBytes(void *p, uint16_t n) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (n--) *v++ = 0;
}
static uint32_t rotateRight(uint32_t x, uint8_t n) {
  return (x >> n) | (x << (32 - n));
}
static const uint32_t shaConstants[64] PROGMEM = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
struct ShaState {
  uint32_t h[8], bytes;
  uint8_t block[64], used;
};
static void shaInit(ShaState &s) {
  const uint32_t init[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                           0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
  memcpy(s.h, init, sizeof(init));
  s.bytes = 0; s.used = 0;
}
static void shaBlock(ShaState &s) {
  uint32_t w[16];
  for (uint8_t i=0; i<16; i++) {
    uint8_t j=i*4;
    w[i]=((uint32_t)s.block[j]<<24)|((uint32_t)s.block[j+1]<<16)|
         ((uint32_t)s.block[j+2]<<8)|s.block[j+3];
  }
  uint32_t a=s.h[0],b=s.h[1],c=s.h[2],d=s.h[3];
  uint32_t e=s.h[4],f=s.h[5],g=s.h[6],h=s.h[7];
  for (uint8_t i=0; i<64; i++) {
    if (i>=16) {
      uint32_t x=w[(i-15)&15],y=w[(i-2)&15];
      w[i&15] += (rotateRight(x,7)^rotateRight(x,18)^(x>>3))+
                   w[(i-7)&15]+(rotateRight(y,17)^rotateRight(y,19)^(y>>10));
    }
    uint32_t t1=h+(rotateRight(e,6)^rotateRight(e,11)^rotateRight(e,25))+
                 ((e&f)^((~e)&g))+pgm_read_dword(&shaConstants[i])+w[i&15];
    uint32_t t2=(rotateRight(a,2)^rotateRight(a,13)^rotateRight(a,22))+
                 ((a&b)^(a&c)^(b&c));
    h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
  }
  s.h[0]+=a;s.h[1]+=b;s.h[2]+=c;s.h[3]+=d;
  s.h[4]+=e;s.h[5]+=f;s.h[6]+=g;s.h[7]+=h;
  wipeBytes(w,sizeof(w));
}
static void shaAdd(ShaState &s,const uint8_t *data,uint16_t n) {
  while(n--) {
    s.block[s.used++]=*data++;s.bytes++;
    if(s.used==64) {shaBlock(s);s.used=0;}
  }
}
static void shaFinish(ShaState &s,uint8_t out[32]) {
  uint64_t bits=(uint64_t)s.bytes*8;
  s.block[s.used++]=0x80;
  if(s.used>56) {
    while(s.used<64)s.block[s.used++]=0;
    shaBlock(s);s.used=0;
  }
  while(s.used<56)s.block[s.used++]=0;
  for(uint8_t i=0;i<8;i++)s.block[63-i]=(uint8_t)(bits>>(i*8));
  shaBlock(s);
  for(uint8_t i=0;i<32;i++)out[i]=(uint8_t)(s.h[i/4]>>(24-8*(i%4)));
  wipeBytes(&s,sizeof(s));
}
static void sha256(const uint8_t *data,uint16_t n,uint8_t out[32]) {
  ShaState s;shaInit(s);shaAdd(s,data,n);shaFinish(s,out);
}
static void hmac256(const uint8_t *key,uint8_t keyLen,
                    const uint8_t *data,uint16_t n,uint8_t out[32]) {
  // Locker keys are PINs of at most 8 characters; this helper accepts up to 64.
  uint8_t pad[64]={0},inner[32];
  if(keyLen>64) {sha256(key,keyLen,pad);} else memcpy(pad,key,keyLen);
  for(uint8_t i=0;i<64;i++)pad[i]^=0x36;
  ShaState s;shaInit(s);shaAdd(s,pad,64);shaAdd(s,data,n);shaFinish(s,inner);
  for(uint8_t i=0;i<64;i++)pad[i]^=0x36^0x5c;
  shaInit(s);shaAdd(s,pad,64);shaAdd(s,inner,32);shaFinish(s,out);
  wipeBytes(pad,sizeof(pad));wipeBytes(inner,sizeof(inner));
}
static void pinFingerprint(const char *pin,uint8_t n,const uint8_t salt[16],
                           uint16_t rounds,uint8_t out[32]) {
  uint8_t first[20],u[32];
  memcpy(first,salt,16);first[16]=first[17]=first[18]=0;first[19]=1;
  hmac256((const uint8_t *)pin,n,first,20,u);
  memcpy(out,u,32);
  for(uint16_t i=1;i<rounds;i++) {
    hmac256((const uint8_t *)pin,n,u,32,u);
    for(uint8_t j=0;j<32;j++)out[j]^=u[j];
  }
  wipeBytes(first,sizeof(first));wipeBytes(u,sizeof(u));
}
//SHA-256 calculation
static void pinHash(const char *pin,uint8_t n,const uint8_t addedValue[16],
                    uint8_t out[32]) {
  ShaState s;shaInit(s);
  shaAdd(s,addedValue,16);
  shaAdd(s,(const uint8_t *)pin,n);
  shaFinish(s,out);
}
static bool equalBytes(const uint8_t *a,const uint8_t *b,uint8_t n) {
  uint8_t diff=0;for(uint8_t i=0;i<n;i++)diff|=a[i]^b[i];
  return diff==0;
}






//Back-up power
//Two records keep the previous PIN usable in case power fails mid-write
static const uint8_t RECORD_BYTES=64;
static const int SLOT_A=64,SLOT_B=128,PROVISIONED_ADDRESS=20;
static uint8_t secureRecord[RECORD_BYTES];
static int activeRecord=-1;
static bool credentialFault=false;
static uint16_t lastPinWorkMs=0;
// Public device salt seed, generated on the build computer; not a secret.
// Generate a different seed for each physical locker. Do not reset the counter.
static const uint8_t deviceSeed[16] PROGMEM = {0x4d,0x41,0x05,0x26,0x50,0x52,0x55,0x49,0xb6,0xf4,0x33,0xf9,0xf0,0x36,0x5d,0x0f};


byte readEEPROM(int address);
void writeEEPROM(int address,byte data);
static uint16_t recordCRC(const uint8_t *p,uint8_t n) {
  uint16_t crc=0xffff;
  while(n--) {
    crc^=(uint16_t)*p++<<8;
    for(uint8_t i=0;i<8;i++)crc=(crc&0x8000)?(crc<<1)^0x1021:crc<<1;
  }
  return crc;
}
static uint32_t recordSequence(const uint8_t *r) {
  return (uint32_t)r[3]|((uint32_t)r[4]<<8)|((uint32_t)r[5]<<16)|((uint32_t)r[6]<<24);
}
static uint16_t recordRounds(const uint8_t *r) {
  return (uint16_t)r[7]|((uint16_t)r[8]<<8);
}
static bool validRecord(const uint8_t *r) {
  if(r[0]!=0xd7)return false;
  if(r[1]==2) {
    if(r[2]!=4 || recordRounds(r)!=0)return false; //SHA-256 record.
  } else if(r[1]==1) {
    // Read old records so owner can still unlock/change PIN.
    if(r[2]<4 || r[2]>8 || recordRounds(r)<1 || recordRounds(r)>10000)return false;
  } else return false;
  uint16_t crc=recordCRC(r+1,56);
  return r[57]==(uint8_t)crc && r[58]==(uint8_t)(crc>>8);
}
static void readRecord(int address,uint8_t *r) {
  for(uint8_t i=0;i<RECORD_BYTES;i++)r[i]=readEEPROM(address+i);
}
static void eraseRecord(int address) {
  writeEEPROM(address,0); // Invalidate prior to erasing old hash.
  for(uint8_t i=1;i<RECORD_BYTES;i++)writeEEPROM(address+i,0);
}
static void eraseLegacyPIN() {
  //previously: addresses 0..3 and marker 10.
  for(uint8_t i=0;i<=10;i++)writeEEPROM(i,0);
}
static bool storePIN(const char *pin,uint8_t n) {
  if(n!=4)return false;
  for(uint8_t i=0;i<n;i++)if(pin[i]<'0'||pin[i]>'9')return false;
  uint8_t next[RECORD_BYTES]={0};
  uint32_t seq=activeRecord<0?1:recordSequence(secureRecord)+1;
  if(!seq)return false;
  next[1]=2;next[2]=n; //one SHA-256 calculation.
  for(uint8_t i=0;i<4;i++)next[3+i]=(uint8_t)(seq>>(8*i));
  next[7]=next[8]=0; 
  uint8_t saltInput[20],saltHash[32];
  for(uint8_t i=0;i<16;i++)saltInput[i]=pgm_read_byte(deviceSeed+i);
  memcpy(saltInput+16,next+3,4);
  sha256(saltInput,20,saltHash);memcpy(next+9,saltHash,16);
  unsigned long began=millis();
  pinHash(pin,n,next+9,next+25);
  lastPinWorkMs=(uint16_t)(millis()-began);
  uint16_t crc=recordCRC(next+1,56);
  next[57]=(uint8_t)crc;next[58]=(uint8_t)(crc>>8);
  int dest=(activeRecord==SLOT_A)?SLOT_B:SLOT_A;
  writeEEPROM(dest,0);
  for(uint8_t i=1;i<RECORD_BYTES;i++)writeEEPROM(dest+i,next[i]);
  bool good=true;
  for(uint8_t i=1;i<RECORD_BYTES;i++)if(readEEPROM(dest+i)!=next[i])good=false;
  if(good) {
    writeEEPROM(dest,0xd7);
    if(readEEPROM(dest)!=0xd7)good=false;
  }
  if(good) {
    int old=activeRecord;next[0]=0xd7;memcpy(secureRecord,next,RECORD_BYTES);
    activeRecord=dest;writeEEPROM(PROVISIONED_ADDRESS,0x5a);
    if(old>=0)eraseRecord(old);
    eraseLegacyPIN();
  }
  wipeBytes(next,sizeof(next));wipeBytes(saltInput,sizeof(saltInput));
  wipeBytes(saltHash,sizeof(saltHash));
  return good;
}
static bool verifyPIN(const char *pin,uint8_t n) {
  if(activeRecord<0 || n!=secureRecord[2])return false;
  uint8_t test[32];unsigned long began=millis();
  if(secureRecord[1]==2)pinHash(pin,n,secureRecord+9,test);
  else pinFingerprint(pin,n,secureRecord+9,recordRounds(secureRecord),test);
  bool match=equalBytes(test,secureRecord+25,32);wipeBytes(test,sizeof(test));
  if(match && secureRecord[1]==1 && n==4) {
    //Convert authenticated old PIN without changing its digits
    storePIN(pin,n);
  }
  lastPinWorkMs=(uint16_t)(millis()-began);
  return match;
}
static bool loadSecurePIN() {
  uint8_t a[RECORD_BYTES],b[RECORD_BYTES];
  readRecord(SLOT_A,a);readRecord(SLOT_B,b);
  bool va=validRecord(a),vb=validRecord(b);
  if(va||vb) {
    bool pickB=vb&&(!va||recordSequence(b)>recordSequence(a));
    memcpy(secureRecord,pickB?b:a,RECORD_BYTES);activeRecord=pickB?SLOT_B:SLOT_A;
    writeEEPROM(PROVISIONED_ADDRESS,0x5a);
    if(va&&vb)eraseRecord(pickB?SLOT_A:SLOT_B);
    eraseLegacyPIN();
  } else {
    activeRecord=-1;
    //Fail closed if a once-provisioned device has lost its credentials
    if(readEEPROM(PROVISIONED_ADDRESS)==0x5a)credentialFault=true;
    else if(readEEPROM(10)==0xa5) {
      char legacy[4];bool valid=true;
      for(uint8_t i=0;i<4;i++) {
        uint8_t x=readEEPROM(i);
        if(x>9)valid=false;
        legacy[i]='0'+x;
      }
      if(valid) {if(!storePIN(legacy,4))credentialFault=true;}
      else credentialFault=true;
      wipeBytes(legacy,sizeof(legacy));
    }
  }
  wipeBytes(a,sizeof(a));wipeBytes(b,sizeof(b));
  return activeRecord>=0;
}


void setupServoPower();
void turnServoOn();
void turnServoOff();
void setupFeedback();
void motionFeedback(byte result);
void stopBuzzer();
const int keypadPin = A0;
const int servoPin = 9; //D9/OC1A, physical pin 15
const int senseBeforePin = A1; //pin 24
const int senseAfterPin = A2;  //pin 25


const int keyADC[12] = {
  11, 457, 632,
  176, 513, 660,
  296, 560, 684,
  385, 597, 705
};


const char keyNames[12] = {
  '1', '2', '3',
  '4', '5', '6',
  '7', '8', '9',
  '*', '0', '#'
};


const int keyTolerance = 8;
const int noButtonThreshold = 900;
bool buttonWasPressed = false;


char enteredPassword[9]={0};
char newPassword[9]={0};
byte enteredIndex=0,newPasswordIndex=0;
bool passwordStored=false;


typedef enum {
  IDLE,
  ENTER_PASSWORD,
  CHECK_PASSWORD,
  ERROR_STATE,
  UNLOCKED,
  LOCKED,
  CHANGE_PASSWORD
} state_t;


state_t state = LOCKED;


//initial settings based on the normal and blocked measurements.
const float blockThresholdCounts = 24.0;
const unsigned long startupIgnoreMs = 100;
const unsigned long blockConfirmMs = 80;
const unsigned long forwardLimitMs = 500;
const unsigned long totalMotionLimitMs = 980;
const unsigned long endpointSettleMs = 50;
const unsigned long timedTestForwardMs = 450;


const float senseResistance = 0.5;
const float adcReferenceVoltage = 5.0;
const unsigned long currentSampleInterval = 5;
const byte currentWindowSize = 8; //40 ms of readings
int currentWindow[currentWindowSize];
long currentWindowSum = 0;
byte currentWindowCount = 0, currentWindowIndex = 0;
unsigned long lastCurrentReading = 0;
bool freshCurrentSample = false;
int beforeADC = 0, afterADC = 0, currentDifference = 0;
float averageDifference = 0.0;
const int servoStepUs = 50;
const unsigned long servoStepInterval = 20;
int servoPulseUs = 1000, servoTargetPulseUs = 1000;
int settledPulseUs = 1000, previousPulseUs = 1000;
unsigned long lastServoStep = 0;
bool motionActive = false, motionReturning = false, motionFault = false;
bool forceRoundTrip = false, endpointSeen = false;
unsigned long motionStarted = 0, endpointSince = 0;
bool timingHigh = false, timingLow = false;
unsigned long highSince = 0, lowSince = 0;
//return 1 = current blockage
//return 2 = timed test
//return 3 = timeout
byte returnReason = 0;


//short logs with a final result
const unsigned long currentLogDurationMs = 2000;
const unsigned long currentPrintIntervalMs = 25;
bool currentLogActive = false;
unsigned long currentLogStarted = 0, lastCurrentPrint = 0;
int logPeakDifference = -1024;
float logPeakAverage = -1024.0, forwardPeakAverage = 0.0;
unsigned long longestHighMs = 0, detectedAfterMs = 0, recordedMoveMs = 0;
//0 idle
//1 moving
//2 OK
//3 blockage returned
//4 timed return,
// 5 timeout returned
//6 fault. Position sensor unavailable.
byte recordedResult = 0;


//power saving separate from the seven locker states.
const unsigned long idleTimeoutMs = IDLE_TIMEOUT_MS;
const unsigned long sleepingKeyScanMs = 20;
bool automaticSleepEnabled = true;
bool idlePowerSaving = false;
unsigned long lastActivityMs = 0, lastSleepKeyScan = 0;
byte awakeADCSRA = 0, awakePRR = 0, awakeACSR = 0, awakeDIDR0 = 0;
Feedback feedback=FEEDBACK_NONE;
unsigned long feedbackStarted=0;
uint8_t feedbackToneStep=255;
bool uiSleeping=false;
float lastBatteryV=0;
bool batteryLow=false,batteryWarnedThisWake=false;
unsigned long batteryCheckedAt=0;
bool batteryCheckDue=true;
bool servoPowered=true;
bool deepSleepAllowed=false;
uint8_t incorrectAttempts=0;
bool keypadLockout=false;
unsigned long lockoutStarted=0;
bool confirmingPIN=false;
char confirmPassword[9]={0};
byte confirmIndex=0;


ISR(TIMER2_COMPA_vect) {
  //D3: PD3 on the DIP ATmega328P.
  PORTD ^= _BV(PD3);
}
void stopBuzzer() {
  TIMSK2=0;TCCR2A=0;TCCR2B=0;digitalWrite(buzzerPin,LOW);
}
void startBuzzer(uint16_t frequency) {
  stopBuzzer();
  if(!ENABLE_BUZZER || !frequency)return;
  uint16_t count=F_CPU/(128UL*frequency)-1;
  if(count>255)count=255;
  TCNT2=0;OCR2A=(uint8_t)count;
  TCCR2A=_BV(WGM21);TCCR2B=_BV(CS22);TIMSK2=_BV(OCIE2A);
}
void showFeedback(Feedback event) {
  feedback=event;feedbackStarted=millis();feedbackToneStep=255;
  stopBuzzer();
}
void allFeedbackOff() {
  stopBuzzer();feedback=FEEDBACK_NONE;
  digitalWrite(redLedPin,LOW);digitalWrite(greenLedPin,LOW);
}
void serviceFeedback() {
  if(uiSleeping) {allFeedbackOff();return;}
  unsigned long now=millis(),age=now-feedbackStarted;
  //short, silent flash demonstrates that locker has woken up
  unsigned long duration=feedback==FEEDBACK_WAKE?500:1000;
  if(feedback!=FEEDBACK_NONE && age>=duration) {
    feedback=FEEDBACK_NONE;stopBuzzer();
  }
  if(feedback!=FEEDBACK_NONE) {
    uint8_t step=age/160;
    if(step!=feedbackToneStep) {
      feedbackToneStep=step;stopBuzzer();
      bool rising=feedback==FEEDBACK_OK||feedback==FEEDBACK_CHANGED;
      bool warn=feedback==FEEDBACK_LOW||feedback==FEEDBACK_BLOCKED||feedback==FEEDBACK_FAULT;
      if(rising && (step==0||step==2||(feedback==FEEDBACK_CHANGED&&step==4)))
        startBuzzer(1200+step*300);
      else if(feedback==FEEDBACK_WRONG && step<3)startBuzzer(600);
      else if(warn && (step==0||step==2||step==4))startBuzzer(1000);
    }
  }
  bool red=false,green=false;
  if(feedback==FEEDBACK_WAKE) {red=true;green=true;}
  else if(feedback==FEEDBACK_WRONG || feedback==FEEDBACK_LOW ||
     feedback==FEEDBACK_BLOCKED || feedback==FEEDBACK_FAULT)red=(age%320)<160;
  else if(feedback==FEEDBACK_CHANGED) {red=(age%320)<160;green=!red;}
  else if(feedback==FEEDBACK_OK)green=true;
  else if(motionFault)red=(now%1000)<200;
  else if(keypadLockout)red=(now%1000)<100;
  else if(state==CHANGE_PASSWORD) {red=(now%600)<300;green=!red;}
  else if(state==ENTER_PASSWORD||state==CHECK_PASSWORD)green=(now%800)<400;
  else if(settledPulseUs==2000)green=true;
  else red=true;
  digitalWrite(redLedPin,ENABLE_LEDS&&red?HIGH:LOW);
  digitalWrite(greenLedPin,ENABLE_LEDS&&green?HIGH:LOW);
}
void setupFeedback() {
  pinMode(redLedPin,OUTPUT);pinMode(greenLedPin,OUTPUT);pinMode(buzzerPin,OUTPUT);
  allFeedbackOff();
}
void turnServoOff() {
  //Stop signal before cutting power
//avoids feeding the servo through D9
  TCCR1A &= ~(_BV(COM1A1)|_BV(COM1A0));digitalWrite(servoPin,LOW);
  if(HAS_SERVO_POWER_SWITCH) {
    digitalWrite(servoPowerPin,HIGH);servoPowered=false;
  }
}
void turnServoOn() {
  if(!servoPowered && HAS_SERVO_POWER_SWITCH) {
    digitalWrite(servoPowerPin,LOW);
    delay(20); // Supply settling only
  }
  servoPowered=true;
  TCNT1=0;OCR1A=servoPulseUs*2;
  TCCR1A=(1<<COM1A1)|(1<<WGM11);
  TCCR1B=(1<<WGM13)|(1<<WGM12)|(1<<CS11);
}
void checkBattery() {
  if(!ENABLE_BATTERY_MONITOR||motionActive||currentLogActive)return;
  unsigned long now=millis();
  if(!batteryCheckDue && now-batteryCheckedAt<BATTERY_INTERVAL_MS)return;
  analogRead(batteryPin);
  delayMicroseconds(200);
  uint16_t sum=0;
  for(byte i=0;i<8;i++)sum+=analogRead(batteryPin);
  lastBatteryV=(sum/8.0)*(ADC_REFERENCE_V/1024.0)*
                ((BATTERY_TOP_OHM+BATTERY_BOTTOM_OHM)/BATTERY_BOTTOM_OHM);
  batteryCheckedAt=now;batteryCheckDue=false;
  if(lastBatteryV<LOW_BATTERY_V)batteryLow=true;
  else if(lastBatteryV>BATTERY_CLEAR_V)batteryLow=false;
  Serial.print(F("BATTERY,V,"));Serial.println(lastBatteryV,2);
  if(batteryLow&&!batteryWarnedThisWake&&feedback==FEEDBACK_NONE) {
    showFeedback(FEEDBACK_LOW);batteryWarnedThisWake=true;
  } else if(batteryLow&&!batteryWarnedThisWake)batteryCheckDue=true;
}
void setupServoPower() {
  //PMOS gate high before making the pin an output.
  digitalWrite(servoPowerPin,HIGH);pinMode(servoPowerPin,OUTPUT);
  servoPowered=!HAS_SERVO_POWER_SWITCH;
}
void clearPINBuffers() {
  wipeBytes(enteredPassword,sizeof(enteredPassword));enteredIndex=0;
  wipeBytes(newPassword,sizeof(newPassword));newPasswordIndex=0;
  wipeBytes(confirmPassword,sizeof(confirmPassword));confirmIndex=0;
  confirmingPIN=false;
}




void motionFeedback(byte result) {
  if(result==2)showFeedback(FEEDBACK_OK);
  else if(result==3||result==5)showFeedback(FEEDBACK_BLOCKED);
  else if(result==6)showFeedback(FEEDBACK_FAULT);
}


void noteActivity() {
  lastActivityMs = millis();
}


void printMotionResult() {
  switch (recordedResult) {
    case 1: Serial.print(F("MOVING")); break;
    case 2: Serial.print(F("MOVE_OK")); break;
    case 3: Serial.print(F("CURRENT_BLOCK_RETURNED")); break;
    case 4: Serial.print(F("TIMED_RETURN")); break;
    case 5: Serial.print(F("TIMEOUT_RETURNED")); break;
    case 6: Serial.print(F("FAULT")); break;
    default: Serial.print(F("IDLE")); break;
  }
}


void startCurrentLogging() {
  noteActivity(); //finish the short log before allowing sleep.
  currentLogStarted = millis();
  lastCurrentPrint = currentLogStarted - currentPrintIntervalMs;
  currentLogActive = true;
  logPeakDifference = -1024;
  logPeakAverage = -1024.0;
  forwardPeakAverage = 0.0;
  longestHighMs = 0;
  detectedAfterMs = 0;
  recordedMoveMs = 0;
  recordedResult = 0;
  Serial.println(F("LOG_START,2000ms"));
}


void resetCurrentWindow() {
  currentWindowSum = 0;
  currentWindowCount = 0;
  currentWindowIndex = 0;
  averageDifference = 0.0;
  freshCurrentSample = false;
  timingHigh = false;
  timingLow = false;
}


//main state follows the completed position command
void applyStableState() {
  enteredIndex = 0;
  if (!passwordStored) state = CHANGE_PASSWORD;
  else state = (settledPulseUs == 1000) ? IDLE : UNLOCKED;
}


void startServoMove(int requestedPulseUs, bool makeRoundTrip) {
  if (motionActive || motionFault) return;
  if (requestedPulseUs != 1000 && requestedPulseUs != 2000) return;
  if (requestedPulseUs == settledPulseUs) {
    applyStableState();
    return;
  }


  turnServoOn();
  startCurrentLogging();
  motionStarted = millis();
  previousPulseUs = settledPulseUs;
  servoTargetPulseUs = requestedPulseUs;
  lastServoStep = motionStarted;
  motionActive = true;
  motionReturning = false;
  forceRoundTrip = makeRoundTrip;
  endpointSeen = false;
  returnReason = 0;
  recordedResult = 1;
  resetCurrentWindow();
  applyStableState();


  Serial.print(F("MOVE_START,"));
  Serial.print(motionStarted);
  Serial.print(','); Serial.print(previousPulseUs);
  Serial.print(','); Serial.println(requestedPulseUs);
}


//all ordinary lock/unlock commands utilize protection logic.
void setServoPulse(int pulseWidthMicroseconds) {
  startServoMove(pulseWidthMicroseconds, false);
}


void servoLocked() { setServoPulse(1000); }
void servoUnlocked() { setServoPulse(2000); }


void setupServoTimer1() {
  pinMode(servoPin, OUTPUT);
  TCCR1A = 0; TCCR1B = 0; TCNT1 = 0;
  ICR1 = 39999;
  //Boot directly commands locked. Path should be clear at power-on.
  //No measured previous physical position at startup.
  OCR1A = servoPulseUs * 2;
  if(HAS_SERVO_POWER_SWITCH)digitalWrite(servoPowerPin,LOW);
  servoPowered=true;
  TCCR1A = (1 << COM1A1) | (1 << WGM11);
  TCCR1B = (1 << WGM13) | (1 << WGM12) | (1 << CS11);
}


void serviceServoRamp() {
  if (motionFault || servoPulseUs == servoTargetPulseUs) return;
  unsigned long now = millis();
  if (now - lastServoStep < servoStepInterval) return;
  lastServoStep = now;
  int change = servoTargetPulseUs - servoPulseUs;
  if (change > servoStepUs) change = servoStepUs;
  if (change < -servoStepUs) change = -servoStepUs;
  servoPulseUs += change;
  OCR1A = servoPulseUs * 2;
}


void beginServoReturn(byte reason) {
  //Change target before printing status.
  servoTargetPulseUs = previousPulseUs;
  lastServoStep = millis();
  motionReturning = true;
  endpointSeen = false;
  returnReason = reason;
  resetCurrentWindow();
  Serial.print(F("RETURN,")); Serial.print(millis());
  if (reason == 1) Serial.println(F(",CURRENT_BLOCK"));
  else if (reason == 2) Serial.println(F(",TIMED_TEST"));
  else Serial.println(F(",MOVE_TIMEOUT"));
}


void finishServoMove(int completedPulseUs, byte result) {
  settledPulseUs = completedPulseUs;
  recordedMoveMs = millis() - motionStarted;
  recordedResult = result;
  motionActive = false;
  motionReturning = false;
  noteActivity(); //Restarts the 30-second inactivity timeout.
  motionFeedback(result);
  applyStableState();
  Serial.print(F("MOVE_DONE,")); Serial.print(recordedMoveMs);
  Serial.print(','); printMotionResult(); Serial.println();
}


void latchServoFault() {
  //stops PWM.
//this is not a servo power switch.
  TCCR1A &= ~((1 << COM1A1) | (1 << COM1A0));
  digitalWrite(servoPin, LOW);
  recordedMoveMs = millis() - motionStarted;
  recordedResult = 6;
  motionActive = false;
  motionFault = true;
  turnServoOff();motionFeedback(6);
  Serial.println(F("FAULT: remove servo power and clear the mechanism."));
}


void serviceServoMotion() {
  if (!motionActive) return;
  unsigned long now = millis();
  unsigned long elapsed = now - motionStarted;
  if (elapsed >= totalMotionLimitMs) { latchServoFault(); return; }


  // Use each ADC sample once. Timing still uses millis, never delay().
  if (freshCurrentSample) {
    freshCurrentSample = false;
    bool valid = currentWindowCount == currentWindowSize;
    if (!motionReturning && elapsed < startupIgnoreMs) valid = false;


    if (!valid) {
      timingHigh = timingLow = false;
    } else if (averageDifference >= blockThresholdCounts) {
      timingLow = false;
      if (!timingHigh) { timingHigh = true; highSince = now; }
      if (!motionReturning) {
        unsigned long highMs = now - highSince;
        if (highMs > longestHighMs) longestHighMs = highMs;
      }
    } else {
      timingHigh = false;
      if (!timingLow) { timingLow = true; lowSince = now; }
    }
  }


  if (!motionReturning && timingHigh && now - highSince >= blockConfirmMs) {
    detectedAfterMs = elapsed;
    if (now - highSince > longestHighMs) longestHighMs = now - highSince;
    beginServoReturn(1);
  }


  if (!motionReturning) {
    if (forceRoundTrip && elapsed >= timedTestForwardMs) {
      beginServoReturn(2);
    } else if (elapsed >= forwardLimitMs) {
      beginServoReturn(3);
    }
  }


  if (servoPulseUs == servoTargetPulseUs) {
    if (!endpointSeen) { endpointSeen = true; endpointSince = now; }
    unsigned long lowRequiredMs = motionReturning ? 20 : 40;
    bool settled = now - endpointSince >= endpointSettleMs &&
                   timingLow && now - lowSince >= lowRequiredMs;
    if (settled) {
      if (motionReturning) {
        byte result = (returnReason == 1) ? 3 : ((returnReason == 2) ? 4 : 5);
        finishServoMove(previousPulseUs, result);
      } else if (!forceRoundTrip) {
        finishServoMove(servoTargetPulseUs, 2);
      }
    }
  } else {
    endpointSeen = false;
  }


  // Return current can stay high while the ramp unwinds the blocked command.
  // Judge its settled current at the old endpoint. The program never waits beyond this limit.
}


void startTimedServoTest() {
  if (motionActive || motionFault) return;
  if (millis() - lastServoStep < 150) {
    Serial.println(F("WAIT: let the servo settle first.")); return;
  }
  int oppositePulse = (settledPulseUs == 1000) ? 2000 : 1000;
  startServoMove(oppositePulse, true);
}


//sampling continues after two-second print window
void readAndLogServoCurrent() {
  unsigned long now = millis();
  freshCurrentSample = false;
  if (currentLogActive && now - currentLogStarted >= currentLogDurationMs) {
    currentLogActive = false;
    Serial.print(F("LOG_DONE,peakDiff,")); Serial.print(logPeakDifference);
    Serial.print(F(",peakAvg,")); Serial.print(logPeakAverage, 1);
    Serial.print(F(",forwardAvgMax,")); Serial.print(forwardPeakAverage, 1);
    Serial.print(F(",above24_ms,")); Serial.print(longestHighMs);
    Serial.print(F(",detect_ms,")); Serial.print(detectedAfterMs);
    Serial.print(F(",move_ms,")); Serial.print(recordedMoveMs);
    Serial.print(F(",result,")); printMotionResult(); Serial.println();
  }
  if(!servoPowered)return;
  if (now - lastCurrentReading < currentSampleInterval) return;
  lastCurrentReading = now;


  long beforeTotal = 0, afterTotal = 0;
  for (byte i = 0; i < 4; i++) {
    analogRead(senseBeforePin); beforeTotal += analogRead(senseBeforePin);
    analogRead(senseAfterPin); afterTotal += analogRead(senseAfterPin);
  }
  beforeADC = beforeTotal / 4;
  afterADC = afterTotal / 4;
  currentDifference = beforeADC - afterADC;
  if (currentWindowCount == currentWindowSize)
    currentWindowSum -= currentWindow[currentWindowIndex];
  else currentWindowCount++;
  currentWindow[currentWindowIndex] = currentDifference;
  currentWindowSum += currentDifference;
  currentWindowIndex = (currentWindowIndex + 1) % currentWindowSize;
  averageDifference = (float)currentWindowSum / currentWindowCount;
  freshCurrentSample = true;


  if (motionActive && !motionReturning && now - motionStarted >= startupIgnoreMs &&
      averageDifference > forwardPeakAverage) forwardPeakAverage = averageDifference;
  if (!currentLogActive) return;
  if (currentDifference > logPeakDifference) logPeakDifference = currentDifference;
  if (averageDifference > logPeakAverage) logPeakAverage = averageDifference;
  if (now - lastCurrentPrint < currentPrintIntervalMs || Serial.availableForWrite() < 60) return;
  lastCurrentPrint = now;
  float currentMA = currentDifference * (adcReferenceVoltage / 1024.0) / senseResistance * 1000.0;
  Serial.print(F("CURRENT,")); Serial.print(now);
  Serial.print(','); Serial.print(servoPulseUs);
  Serial.print(','); Serial.print(beforeADC);
  Serial.print(','); Serial.print(afterADC);
  Serial.print(','); Serial.print(currentDifference);
  Serial.print(','); Serial.print(currentMA, 1);
  Serial.print(','); Serial.println(averageDifference, 1);
}


void writeEEPROM(int address, byte data) {
  while (EECR & (1 << EEPE)) {}


  EEAR = address;
  EEDR = data;
  byte oldSREG = SREG;
  noInterrupts();
  EECR |= (1 << EEMPE);
  EECR |= (1 << EEPE);
  SREG = oldSREG;
}


byte readEEPROM(int address) {
  while (EECR & (1 << EEPE)) {}
  EEAR = address;
  EECR |= (1 << EERE);
  return EEDR;
}


void loadPassword() {
  passwordStored=loadSecurePIN();
  Serial.println(passwordStored?F("Protected PIN loaded."):F("Create a PIN: 4 digits, #, repeat, #."));
}


int readSmoothADC() {
  analogRead(keypadPin);
  long total = 0;
  for (int i = 0; i < 15; i++) total += analogRead(keypadPin);
  return total / 15;
}


char getKeyFromADC(int adcValue) {
  int closestIndex = -1;
  int smallestDifference = 1000;


  for (int i = 0; i < 12; i++) {
    int difference = abs(adcValue - keyADC[i]);
    if (difference < smallestDifference) {
      smallestDifference = difference;
      closestIndex = i;
    }
  }


  if (closestIndex != -1 && smallestDifference <= keyTolerance)
    return keyNames[closestIndex];


  return '\0';
}


//Debounce without delay so timed test continues executing.
char readKeypad(bool wakeOnly) {
  static char candidate = '\0';
  static unsigned long candidateSince = 0;
  int adcValue = readSmoothADC();
  unsigned long now = millis();


  if (adcValue >= noButtonThreshold) {
    buttonWasPressed = false;
    candidate = '\0';
    return '\0';
  }
  if (buttonWasPressed) return '\0';


  char key = getKeyFromADC(adcValue);
  if (key == '\0') {
    candidate = '\0';
    return '\0';
  }
  if (key != candidate) {
    candidate = key;
    candidateSince = now;
    return '\0';
  }
  if (now - candidateSince < 30) return '\0';


  buttonWasPressed = true;
  if (wakeOnly && key != '#') return '\0';
  return key;
}


void clearEnteredPassword() {
  wipeBytes(enteredPassword,sizeof(enteredPassword));enteredIndex=0;
}
//Keep the seven locker states
void runStateMachine(char key) {
  if(motionActive||motionFault||credentialFault)return;
  if(keypadLockout) {
    if(millis()-lockoutStarted<30000)return;
    keypadLockout=false;incorrectAttempts=0;
    applyStableState();
  }
  switch(state) {
    case IDLE:
      if(!passwordStored) {
        state=CHANGE_PASSWORD;clearPINBuffers();
        Serial.println(F("CREATE PIN: 4 digits, #, then repeat and #."));
      } else if(key>='0'&&key<='9') {
        clearEnteredPassword();enteredPassword[enteredIndex++]=key;
        state=ENTER_PASSWORD;
      }
      break;
    case ENTER_PASSWORD:
      if(key>='0'&&key<='9') {
        //Old longer PINs remain usable only until changed to a four-digit PIN.
        byte entryLength=activeRecord>=0?secureRecord[2]:4;
        if(enteredIndex<entryLength)enteredPassword[enteredIndex++]=key;
        else {clearEnteredPassword();state=IDLE;showFeedback(FEEDBACK_WRONG);}
      } else if(key=='*') {clearEnteredPassword();state=IDLE;}
      else if(key=='#')state=CHECK_PASSWORD;
      break;
    case CHECK_PASSWORD: {
      //No servo move is active when calculating the PIN fingerprint.
      stopBuzzer();
      Serial.println(F("CHECKING PIN"));
      bool correct=verifyPIN(enteredPassword,enteredIndex);
      clearEnteredPassword();noteActivity();
      Serial.print(F("PIN_WORK_MS,"));Serial.println(lastPinWorkMs);
      if(correct) {
        incorrectAttempts=0;state=IDLE;servoUnlocked();
        //successful entry indication occurs after movement, 
//not only for a correct PIN.
      } else {state=ERROR_STATE;}
      break;
    }
    case ERROR_STATE:
      showFeedback(FEEDBACK_WRONG);
      if(++incorrectAttempts>=3) {
        keypadLockout=true;lockoutStarted=millis();
        Serial.println(F("KEYPAD LOCKOUT,30s"));
      }
      state=IDLE;
      break;
    case UNLOCKED:
      if(key=='*')state=LOCKED;
      else if(key=='#') {
        clearPINBuffers();state=CHANGE_PASSWORD;
        Serial.println(F("NEW PIN: 4 digits, #, then repeat and #."));
      }
      break;
    case LOCKED:
      applyStableState();servoLocked();clearEnteredPassword();
      break;
    case CHANGE_PASSWORD:
      if(key=='*') {
        clearPINBuffers();applyStableState();
      } else if(key>='0'&&key<='9') {
        char *buffer=confirmingPIN?confirmPassword:newPassword;
        byte &count=confirmingPIN?confirmIndex:newPasswordIndex;
        if(count<4)buffer[count++]=key;
        else {clearPINBuffers();showFeedback(FEEDBACK_WRONG);}
      } else if(key=='#') {
        if(!confirmingPIN) {
          if(newPasswordIndex!=4) {showFeedback(FEEDBACK_WRONG);break;}
          confirmingPIN=true;confirmIndex=0;
          Serial.println(F("REPEAT NEW PIN, then #."));
        } else {
          bool match=confirmIndex==newPasswordIndex &&
            equalBytes((const uint8_t *)newPassword,(const uint8_t *)confirmPassword,confirmIndex);
          if(!match) {
            clearPINBuffers();showFeedback(FEEDBACK_WRONG);
            Serial.println(F("PINs differ. Start again."));break;
          }
          stopBuzzer();
          bool saved=storePIN(newPassword,newPasswordIndex);
          clearPINBuffers();noteActivity();
          if(saved) {
            passwordStored=true;state=LOCKED;
            showFeedback(FEEDBACK_CHANGED);
            Serial.println(F("PIN SAVED"));
          } else {
            showFeedback(FEEDBACK_WRONG);
            Serial.println(F("SAVE FAILED. Previous PIN retained if available."));
          }
        }
      }
      break;
  }
}




//Stop servo pulses before either sleep mode. 
//Power stays on without a switch.
volatile bool wakeInterrupt=false;
ISR(WDT_vect) {wakeInterrupt=true;}
ISR(INT0_vect) {wakeInterrupt=true;}


void disableWatchdog() {
  uint8_t old=SREG;cli();
  MCUSR &= ~_BV(WDRF);
  wdt_disable();
  SREG=old;
}
void watchdogOneSecond() {
  uint8_t old=SREG;cli();wdt_reset();MCUSR &= ~_BV(WDRF);
  WDTCSR=_BV(WDCE)|_BV(WDE);
  WDTCSR=_BV(WDIE)|_BV(WDP2)|_BV(WDP1); // Interrupt only; ~1 secon
  SREG=old;
}
void sleepCpuOnce() {
  uint8_t old=SREG;cli();
  if(!(old&_BV(SREG_I))) {SREG=old;return;}
  SMCR=_BV(SE); // Idle
  __asm__ __volatile__("sei\n\tsleep\n\tcli\n\t" ::: "memory");
  SMCR=0;SREG=old;
}
void sleepPowerDownOnce() {
  wakeInterrupt=false;
  if(!DEDICATED_WAKE_BUTTON)watchdogOneSecond();
  cli();
  if(DEDICATED_WAKE_BUTTON&&digitalRead(wakeButtonPin)==LOW) {
    sei();return;
  }
  SMCR=_BV(SE)|_BV(SM1);
#if defined(BODS) && defined(BODSE)
  //Disable BOD for this sleep only
//BOD automatically returns after wake.
  sleep_bod_disable();
#endif
  __asm__ __volatile__("sei\n\tsleep\n\tcli\n\t" ::: "memory");
  SMCR=0;sei();
  if(!DEDICATED_WAKE_BUTTON)disableWatchdog();
}
void leaveIdlePowerSaving() {
  if(deepSleepAllowed&&DEDICATED_WAKE_BUTTON)EIMSK &= ~_BV(INT0);
  PRR=awakePRR;ADCSRA=awakeADCSRA;ACSR=awakeACSR;DIDR0=awakeDIDR0;
  idlePowerSaving=false;uiSleeping=false;
  resetCurrentWindow();lastCurrentReading=millis()-currentSampleInterval;
  //Servo pulses remain stopped until a move is requested.
  batteryCheckDue=true;batteryWarnedThisWake=false;
  noteActivity();
  showFeedback(FEEDBACK_WAKE);
  serviceFeedback(); //both LEDs illuminate as soon as wake is accepted.
  Serial.println(F("WAKE: release wake key, then use keypad."));
}
void enterIdlePowerSaving() {
  clearPINBuffers();applyStableState();
  allFeedbackOff();uiSleeping=true;
  turnServoOff(); //PWM stopped even when servo power remains connected.
  Serial.println(F("SLEEP: # wakes (hold 1.5s in Power-down polling mode)."));
  Serial.flush();
  awakeADCSRA=ADCSRA;awakePRR=PRR;awakeACSR=ACSR;awakeDIDR0=DIDR0;
  DIDR0 |= _BV(ADC0D)|_BV(ADC1D)|_BV(ADC2D)|_BV(ADC3D);
  ACSR |= _BV(ACD);ADCSRA &= ~_BV(ADEN);
  PRR |= _BV(PRADC)|_BV(PRSPI)|_BV(PRTWI)|_BV(PRTIM2);
  if(deepSleepAllowed) {
    //PWM stopped
//Servo power is cut only when a switch is fitted.
    PRR |= _BV(PRTIM0)|_BV(PRTIM1)|_BV(PRUSART0);
    if(DEDICATED_WAKE_BUTTON) {
      EIMSK &= ~_BV(INT0);
      EICRA &= ~(_BV(ISC01)|_BV(ISC00)); // INT0 low-level wake
      EIFR=_BV(INTF0);EIMSK|=_BV(INT0);
    }
  }
  idlePowerSaving=true;lastSleepKeyScan=millis();
}
bool serviceIdlePowerSaving() {
  if(!idlePowerSaving)return false;
  if(deepSleepAllowed) {
    sleepPowerDownOnce();
    if(DEDICATED_WAKE_BUTTON) {
      if(digitalRead(wakeButtonPin)==LOW) {
        leaveIdlePowerSaving();
        //Drains any held key before accepting an input.
        buttonWasPressed=true;
        return false;
      }
      return true;
    }
    PRR &= ~_BV(PRADC);ADCSRA=awakeADCSRA;
    //Read A0 only during brief watchdog wakes
//# not a digital low.
    int raw=readSmoothADC();
    bool pressed=getKeyFromADC(raw)=='#';
    if(pressed) {
      PRR &= ~_BV(PRTIM0); //millisecond/delay runs again for debounce
      delay(35);
      pressed=getKeyFromADC(readSmoothADC())=='#';
    }
    ADCSRA &= ~_BV(ADEN);PRR|=_BV(PRADC);
    if(pressed) {
      buttonWasPressed=true;
      leaveIdlePowerSaving();return false;
    }
    PRR|=_BV(PRTIM0);
    return true;
  }
  // Optional light Idle mode; 
//Defaults to Power-down.
  while(Serial.available()>0)Serial.read();
  if(millis()-lastSleepKeyScan>=sleepingKeyScanMs) {
    lastSleepKeyScan=millis();
    PRR &= ~_BV(PRADC);ADCSRA=awakeADCSRA;
    char key=readKeypad(true);
    ADCSRA &= ~_BV(ADEN);PRR|=_BV(PRADC);
    if(key=='#') {leaveIdlePowerSaving();return false;}
  }
  sleepCpuOnce();return true;
}
void checkIdleTimeout() {
  if(!automaticSleepEnabled||idlePowerSaving||keypadLockout||credentialFault)return;
  if(motionActive||motionFault||currentLogActive||buttonWasPressed||
     feedback!=FEEDBACK_NONE)return;
  if(millis()-lastActivityMs>=idleTimeoutMs)enterIdlePowerSaving();
}




void checkSerialServoTest() {
  if(!ENABLE_BENCH_COMMANDS)return;
  while (Serial.available() > 0) {
    char command = Serial.read();
    if (command == '\n' || command == '\r') continue;
    if (motionActive || motionFault) continue;
    if (command == 'R' || command == 'r') startCurrentLogging();
    else if (command == 'T' || command == 't') { noteActivity(); startTimedServoTest(); }
    else if (command == 'L' || command == 'l') { noteActivity(); servoLocked(); }
    else if (command == 'U' || command == 'u') { noteActivity(); servoUnlocked(); }
    else if (command == 'A' || command == 'a') {
      automaticSleepEnabled = false; // ADDED: hold awake for a current measurement.
      noteActivity();
      Serial.println(F("POWER,AWAKE_HOLD"));
    } else if (command == 'S' || command == 's') {
      automaticSleepEnabled = true;
      noteActivity();
      Serial.print(F("POWER,AUTO_SLEEP,"));
      Serial.print(idleTimeoutMs);
      Serial.println(F("ms"));
    }
  }
}


void setup() {
  MCUSR &= ~_BV(WDRF);wdt_disable();
  Serial.begin(115200);analogReference(DEFAULT);
  pinMode(keypadPin,INPUT);pinMode(senseBeforePin,INPUT);pinMode(senseAfterPin,INPUT);
  pinMode(batteryPin,INPUT);pinMode(wakeButtonPin,INPUT_PULLUP);
  //These two outputs are unconnected in this pin map.
  digitalWrite(6,LOW);pinMode(6,OUTPUT);
  digitalWrite(8,LOW);pinMode(8,OUTPUT);
  for(byte p=10;p<=13;p++)pinMode(p,INPUT_PULLUP);
  if(!ENABLE_SERIAL) {
    pinMode(0,INPUT_PULLUP);digitalWrite(1,LOW);pinMode(1,OUTPUT);
  }
  setupFeedback();setupServoPower();
  loadPassword();
  deepSleepAllowed=ENABLE_DEEP_SLEEP;
  if(credentialFault) {
    motionFault=true;turnServoOff();
    Serial.println(F("CREDENTIAL FAULT: repair EEPROM using programmer. No auto-enrollment."));
    return;
  }
  setupServoTimer1();applyStableState();noteActivity();
  Serial.println(F("Smart Locker M3+M4"));
  Serial.println(F("PIN then # unlocks. Unlocked: * locks, # changes PIN."));
  Serial.println(F("New PIN: exactly 4 digits, #, repeat, #. Old longer PINs work until changed."));
  Serial.println(F("Sleep: 30 seconds, # wakes. Deep polling: hold # about 1.5 seconds."));
  Serial.println(F("Initial motor position is unknown: keep latch clear at power-up."));
  Serial.print(F("CONFIG,battery,"));Serial.print(ENABLE_BATTERY_MONITOR);
  Serial.print(F(",PMOS,"));Serial.print(HAS_SERVO_POWER_SWITCH);
  Serial.print(F(",deep,"));Serial.print(deepSleepAllowed);
  Serial.print(F(",bench,"));Serial.println(ENABLE_BENCH_COMMANDS);
  startCurrentLogging();
}
void loop() {
  if(credentialFault) {serviceFeedback();return;}
  if(serviceIdlePowerSaving())return;
  readAndLogServoCurrent();
  serviceServoRamp();serviceServoMotion();
  checkSerialServoTest();
  char key=readKeypad(false);
  if(key!='\0')noteActivity();
  runStateMachine(key);
  serviceServoRamp();serviceServoMotion();
  checkBattery();serviceFeedback();
  checkIdleTimeout();
}



