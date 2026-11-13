package com.rohan.macremote;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Insets;
import android.view.WindowInsets;
import android.widget.FrameLayout;
import android.net.http.SslError;
import android.os.Bundle;
import android.view.KeyEvent;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

public class MainActivity extends Activity {
    private WebView web;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        web = new WebView(this);
        web.setBackgroundColor(Color.parseColor("#0a0b0e"));
        web.getSettings().setJavaScriptEnabled(true);
        web.setWebViewClient(new WebViewClient() {
            // The Mac uses a self-signed cert. Trust it only if it is exactly the one pinned at build time.
            @Override
            public void onReceivedSslError(WebView v, SslErrorHandler h, SslError e) {
                try {
                    X509Certificate c = e.getCertificate().getX509Certificate();
                    byte[] d = MessageDigest.getInstance("SHA-256").digest(c.getEncoded());
                    StringBuilder hex = new StringBuilder();
                    for (byte x : d) hex.append(String.format("%02x", x));
                    if (hex.toString().equals(BuildConfig.CERT_SHA256)) { h.proceed(); return; }
                } catch (Exception ignored) { }
                h.cancel();
            }
        });
        // Android 15+ draws edge-to-edge; pad so buttons don't sit under the status/nav bars.
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.parseColor("#0a0b0e"));
        root.addView(web);
        root.setOnApplyWindowInsetsListener((v, ins) -> {
            // include the keyboard so the page shrinks above it instead of hiding behind it
            Insets i = ins.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.ime());
            v.setPadding(i.left, i.top, i.right, i.bottom);
            return WindowInsets.CONSUMED;
        });
        setContentView(root);
        web.loadUrl(BuildConfig.MAC_URL);
    }

    // Phone volume buttons control the Mac's volume instead of the phone's.
    @Override
    public boolean dispatchKeyEvent(KeyEvent e) {
        int k = e.getKeyCode();
        if (k == KeyEvent.KEYCODE_VOLUME_UP || k == KeyEvent.KEYCODE_VOLUME_DOWN) {
            if (e.getAction() == KeyEvent.ACTION_DOWN)
                web.evaluateJavascript("post({a:'" + (k == KeyEvent.KEYCODE_VOLUME_UP ? "volup" : "voldown") + "'})", null);
            return true;
        }
        return super.dispatchKeyEvent(e);
    }

    @Override
    protected void onResume() {
        super.onResume();
        web.resumeTimers();
        web.loadUrl(BuildConfig.MAC_URL);  // re-auth + fresh page each time the app is opened
    }

    @Override
    protected void onPause() {
        super.onPause();
        web.pauseTimers();  // no status pings while the app is in the background
    }
}
