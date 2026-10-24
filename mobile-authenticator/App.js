import { useEffect, useState } from 'react';
import { Button, Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import { CameraView, useCameraPermissions } from 'expo-camera';
import * as SecureStore from 'expo-secure-store';
import { generateTOTP, parseOtpauth, secondsRemaining } from './totp';

const STORE_KEY = 'totp_account';

export default function App() {
  const [account, setAccount] = useState(null); // { secret, label }
  const [manual, setManual] = useState('');
  const [scanning, setScanning] = useState(false);
  const [now, setNow] = useState(Date.now());
  const [permission, requestPermission] = useCameraPermissions();

  // Recupera la semilla guardada (sobrevive a cerrar la app, sin red)
  useEffect(() => {
    SecureStore.getItemAsync(STORE_KEY).then(v => v && setAccount(JSON.parse(v)));
  }, []);

  // Reloj local: re-render cada 1 s (el código cambia solo al pasar de 30 a 0)
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const save = async acc => {
    setAccount(acc);
    await SecureStore.setItemAsync(STORE_KEY, JSON.stringify(acc));
  };

  const onScan = ({ data }) => {
    setScanning(false);
    try { save(parseOtpauth(data)); } catch (e) { alert(e.message); }
  };

  if (scanning) {
    return (
      <View style={{ flex: 1 }}>
        <CameraView style={{ flex: 1 }} barcodeScannerSettings={{ barcodeTypes: ['qr'] }} onBarcodeScanned={onScan} />
        <Button title="Cancelar" onPress={() => setScanning(false)} />
      </View>
    );
  }

  if (!account) {
    return (
      <View style={styles.container}>
        <Text style={styles.title}>Mi Authenticator</Text>
        <Button title="Escanear QR" onPress={async () => {
          if (!permission?.granted) { const p = await requestPermission(); if (!p.granted) return; }
          setScanning(true);
        }} />
        <Text style={styles.or}>— o pega la semilla Base32 —</Text>
        <TextInput style={styles.input} value={manual} onChangeText={setManual}
                   autoCapitalize="characters" placeholder="JBSWY3DPEHPK3PXP" />
        <Button title="Guardar semilla" onPress={() => manual && save({ secret: manual.trim(), label: 'Manual' })} />
      </View>
    );
  }

  const secs = secondsRemaining(now);
  const code = generateTOTP(account.secret, now);
  return (
    <View style={styles.container}>
      <Text style={styles.label}>{account.label}</Text>
      <Text style={styles.code}>{code.slice(0, 3)} {code.slice(3)}</Text>
      <View style={styles.barBg}>
        <View style={[styles.bar, { width: `${(secs / 30) * 100}%`, backgroundColor: secs <= 5 ? '#d9534f' : '#2f5bd3' }]} />
      </View>
      <Text style={styles.secs}>{secs}s</Text>
      <Pressable onPress={async () => { await SecureStore.deleteItemAsync(STORE_KEY); setAccount(null); }}>
        <Text style={styles.reset}>Borrar cuenta</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 24, backgroundColor: '#fff' },
  title: { fontSize: 24, fontWeight: '700', marginBottom: 24 },
  or: { marginVertical: 16, color: '#666' },
  input: { borderWidth: 1, borderColor: '#ccc', borderRadius: 8, padding: 10, width: '100%', marginBottom: 8 },
  label: { fontSize: 16, color: '#555' },
  code: { fontSize: 56, fontWeight: '700', letterSpacing: 4, marginVertical: 16, fontVariant: ['tabular-nums'] },
  barBg: { width: '80%', height: 10, backgroundColor: '#e5e7eb', borderRadius: 5, overflow: 'hidden' },
  bar: { height: 10 },
  secs: { marginTop: 8, fontSize: 16 },
  reset: { marginTop: 40, color: '#d9534f' },
});
