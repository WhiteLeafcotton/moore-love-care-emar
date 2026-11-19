
import React, { useState } from "react";

const API = "/api";

export default function ManagerSetup() {
  const [step, setStep] = useState(1);
  const [username, setUsername] = useState("1234");
  const [setupKey, setSetupKey] = useState("");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [qrCode, setQrCode] = useState("");
  const [manualSecret, setManualSecret] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function request(path, body) {
    setLoading(true);
    setError("");
    setMessage("");

    try {
      const response = await fetch(API + path, {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Request failed.");
      }

      return data;
    } catch (err) {
      setError(err.message);
      return null;
    } finally {
      setLoading(false);
    }
  }

  // STEP 1-3
  async function startSetup() {
    const result = await request("/setup/start", {
      username,
      email,
      setupKey
    });

    if (result) {
      setMessage("Verification code sent to your email.");
      setStep(2);
    }
  }

  // STEP 4
  async function verifyEmail() {
    const result = await request("/setup/verify-email", {
      code
    });

    if (result) {
      setMessage("Your email has been verified.");
      setStep(3);
      setCode("");
    }
  }

  // STEP 5
  async function savePassword() {
    const result = await request("/setup/create-password", {
      password,
      confirmPassword
    });

    if (result) {
      setMessage("Password created successfully.");
      setStep(4);
      setPassword("");
      setConfirmPassword("");
    }
  }

  // STEP 6A
  async function setupMFA() {
    const result = await request("/setup/mfa", {});

    if (result) {
      setQrCode(result.qrCode);
      setManualSecret(result.manualSecret);
      setStep(5);
    }
  }

  // STEP 6B-7
  async function activateAccount() {
    const result = await request("/setup/mfa/confirm", {
      code
    });

    if (result) {
      setMessage("Your manager account is now active.");
      setStep(6);
    }
  }

  const inputStyle = {
    width: "100%",
    boxSizing: "border-box",
    padding: 14,
    marginTop: 8,
    marginBottom: 20,
    background: "#101710",
    border: "1px solid #485548",
    borderRadius: 8,
    color: "#ffffff",
    fontSize: 15
  };

  const buttonStyle = {
    width: "100%",
    padding: 15,
    border: 0,
    borderRadius: 8,
    background: "#AD9365",
    color: "#111710",
    fontWeight: 700,
    cursor: "pointer",
    opacity: loading ? 0.6 : 1
  };

  const cardStyle = {
    maxWidth: 470,
    width: "100%",
    padding: 30,
    boxSizing: "border-box",
    borderRadius: 18,
    border: "1px solid #354436",
    background: "#1A211B",
    color: "#F5F5EF"
  };

  function field(label, value, setter, type = "text") {
    return (
      <label style={{ display: "block" }}>
        {label}
        <input
          style={inputStyle}
          type={type}
          value={value}
          onChange={e => setter(e.target.value)}
          required
        />
      </label>
    );
  }

  return (
    <main style={{
      minHeight: "100vh",
      padding: 20,
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      background: "#101510",
      fontFamily: "Inter, sans-serif"
    }}>
      <section style={cardStyle}>
        <header style={{ marginBottom: 30 }}>
          <h1 style={{
            fontSize: 23,
            letterSpacing: 1.5
          }}>
            MOORE LOVE & CARE
          </h1>
          <p style={{ color: "#B7C0B4" }}>
            Secure Manager Enrollment
          </p>
        </header>

        <div style={{
          height: 4,
          background: "#354436",
          borderRadius: 10,
          marginBottom: 28
        }}>
          <div style={{
            width: `${step === 6 ? 100 : step * 20}%`,
            height: "100%",
            background: "#AD9365",
            borderRadius: 10,
            transition: "width .3s"
          }} />
        </div>

        {step === 1 && (
          <>
            <h2>Manager Registration</h2>
            <p>Set up the initial company manager account.</p>

            {field("Manager Username", username, setUsername)}
            {field("Company Email", email, setEmail, "email")}
            {field("One-time Setup Authorization Key",
              setupKey, setSetupKey, "password")}

            <button
              style={buttonStyle}
              disabled={loading}
              onClick={startSetup}
            >
              {loading ? "Sending..." : "Send Verification Code"}
            </button>
          </>
        )}

        {step === 2 && (
          <>
            <h2>Verify Your Email</h2>
            <p>
              Enter the six-digit code sent to {email}.
            </p>

            {field("Verification Code", code, setCode, "text")}

            <button
              style={buttonStyle}
              disabled={loading}
              onClick={verifyEmail}
            >
              Verify Email
            </button>
          </>
        )}

        {step === 3 && (
          <>
            <h2>Create Your Password</h2>
            <p>
              Choose a strong password of at least 12 characters.
            </p>

            {field("New Password", password, setPassword, "password")}
            {field("Confirm Password",
              confirmPassword, setConfirmPassword, "password")}

            <button
              style={buttonStyle}
              disabled={loading}
              onClick={savePassword}
            >
              Save Password
            </button>
          </>
        )}

        {step === 4 && (
          <>
            <h2>Set Up Multi-Factor Authentication</h2>
            <p>
              You will use an authenticator app to secure future logins.
            </p>

            <button
              style={buttonStyle}
              disabled={loading}
              onClick={setupMFA}
            >
              Generate MFA Enrollment
            </button>
          </>
        )}

        {step === 5 && (
          <>
            <h2>Scan Your Authenticator QR Code</h2>

            <p>
              Scan this code using an authenticator app on your phone.
            </p>

            {qrCode && (
              <img
                src={qrCode}
                alt="Authenticator enrollment QR code"
                style={{
                  width: 210,
                  maxWidth: "100%",
                  display: "block",
                  margin: "20px auto",
                  background: "white",
                  padding: 12,
                  borderRadius: 10
                }}
              />
            )}

            <p style={{ fontSize: 13, color: "#B7C0B4" }}>
              Manual setup key (keep private):
            </p>

            <div style={{
              background: "#101710",
              padding: 12,
              overflowWrap: "anywhere",
              borderRadius: 8,
              fontSize: 13
            }}>
              {manualSecret}
            </div>

            {field("Six-digit Authenticator Code",
              code, setCode)}

            <button
              style={buttonStyle}
              disabled={loading}
              onClick={activateAccount}
            >
              Verify MFA & Activate Account
            </button>
          </>
        )}

        {step === 6 && (
          <>
            <h2>Account Activated</h2>
            <p>
              Your Moore Love & Care manager account has
              been successfully enrolled.
            </p>

            <button
              style={buttonStyle}
              onClick={() => window.location.assign("/manager")}
            >
              Enter Manager Dashboard
            </button>
          </>
        )}

        {error && (
          <p style={{ color: "#FF9999", marginTop: 20 }}>
            {error}
          </p>
        )}

        {message && (
          <p style={{ color: "#A9D3A8", marginTop: 20 }}>
            {message}
          </p>
        )}

        <footer style={{
          marginTop: 35,
          color: "#899489",
          fontSize: 12,
          textAlign: "center"
        }}>
          Moore Love & Care eMAR | Secure Enrollment
        </footer>
      </section>
    </main>
  );
}

