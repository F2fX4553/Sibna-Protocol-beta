from fpdf import FPDF
import os
from datetime import datetime

# Configuration
TITLE = "Obsidian Sovereign Security Whitepaper"
VERSION = "1.0.0"
DATE = datetime.now().strftime("%B %Y")
AUTHOR = "Obsidian Sovereign Team"

class WhitepaperPDF(FPDF):
    def header(self):
        if self.page_no() > 1:
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(128)
            self.cell(0, 10, f'{TITLE} v{VERSION}', 0, 0, 'R')
            self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, num, label):
        self.set_font('Helvetica', 'B', 16)
        self.set_text_color(0, 255, 157)  # Neon Green
        self.cell(0, 10, f'{num}. {label}', 0, 1, 'L')
        self.ln(4)
        # Line separator
        self.set_draw_color(123, 97, 255) # Purple
        self.set_line_width(0.5)
        self.line(self.get_x(), self.get_y(), 200, self.get_y())
        self.ln(10)

    def chapter_body(self, body):
        self.set_font('Times', '', 11)
        self.set_text_color(255, 255, 255) # White text
        self.multi_cell(0, 6, body)
        self.ln()

    def add_image_centered(self, image_path, width=150):
        if os.path.exists(image_path):
            self.image(image_path, x=(210-width)/2, w=width)
            self.ln(10)
        else:
            print(f"Warning: Image not found at {image_path}")

def create_pdf():
    pdf = WhitepaperPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Set dark background for all pages
    pdf.set_fill_color(10, 10, 10) # #0a0a0a
    
    # --- Cover Page ---
    pdf.add_page()
    pdf.rect(0, 0, 210, 297, 'F') # Fill background
    
    # Logo/Title
    pdf.ln(60)
    pdf.set_font('Helvetica', 'B', 32)
    pdf.set_text_color(0, 255, 157) # Neon Green
    pdf.cell(0, 20, "OBSIDIAN SOVEREIGN", 0, 1, 'C')
    
    pdf.set_font('Helvetica', 'B', 24)
    pdf.set_text_color(123, 97, 255) # Purple
    pdf.cell(0, 15, "Security Whitepaper", 0, 1, 'C')
    
    pdf.ln(20)
    pdf.set_font('Helvetica', '', 12)
    pdf.set_text_color(200, 200, 200)
    pdf.cell(0, 10, f"Version {VERSION}", 0, 1, 'C')
    pdf.cell(0, 10, DATE, 0, 1, 'C')
    
    # --- Content Pages ---
    pdf.add_page()
    pdf.rect(0, 0, 210, 297, 'F')
    
    # 1. Introduction
    pdf.chapter_title(1, 'Introduction')
    pdf.chapter_body(
        "Obsidian Sovereign is a next-generation secure communication protocol designed to operate in hostile network environments. "
        "Unlike traditional VPNs or TLS implementations, Obsidian Sovereign prioritizes stealth, deniability, and resistance to traffic analysis.\n\n"
        "The protocol is built upon the Noise Protocol Framework (Noise_XK_25519_ChaChaPoly_BLAKE2s) and integrates advanced traffic obfuscation "
        "techniques to mimic benign HTTP/1.1 traffic."
    )
    
    # 2. Architecture
    pdf.chapter_title(2, 'System Architecture')
    pdf.chapter_body(
        "The system follows a layered architecture designed to separate concerns between application logic, "
        "cryptographic operations, and transport obfuscation."
    )
    pdf.add_image_centered('docs/images/architecture.png', width=160)
    
    # 3. Cryptographic Primitives
    pdf.chapter_title(3, 'Cryptographic Primitives')
    pdf.chapter_body(
        "Obsidian Sovereign uses a conservative selection of modern, high-performance cryptographic primitives:\n"
    )
    
    # Table
    pdf.set_fill_color(45, 45, 45)
    pdf.set_text_color(0, 255, 157)
    pdf.set_font('Helvetica', 'B', 10)
    pdf.cell(60, 10, 'Component', 1, 0, 'C', 1)
    pdf.cell(60, 10, 'Primitive', 1, 0, 'C', 1)
    pdf.cell(70, 10, 'Implementation', 1, 1, 'C', 1)
    
    pdf.set_fill_color(30, 30, 30)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font('Helvetica', '', 10)
    
    data = [
        ('Key Exchange', 'X25519', 'ECDH (Curve25519)'),
        ('Encryption', 'ChaCha20-Poly1305', 'AEAD (IETF Variant)'),
        ('Hashing', 'BLAKE2s', 'Cryptographic Hash'),
        ('Key Derivation', 'HKDF', 'HMAC-based KDF')
    ]
    
    for row in data:
        pdf.cell(60, 10, row[0], 1, 0, 'L', 1)
        pdf.cell(60, 10, row[1], 1, 0, 'L', 1)
        pdf.cell(70, 10, row[2], 1, 1, 'L', 1)
        
    pdf.ln(10)

    # 4. Protocol Flow
    pdf.chapter_title(4, 'Protocol Handshake')
    pdf.chapter_body(
        "The protocol uses the Noise_XK pattern. The client knows the server's static public key, "
        "but the server learns the client's identity only after decryption."
    )
    pdf.add_image_centered('docs/images/handshake.png', width=140)
    
    # 5. Packet Structure
    pdf.chapter_title(5, 'Packet Structure')
    pdf.chapter_body(
        "To evade Deep Packet Inspection (DPI), all Obsidian Sovereign packets are encapsulated within valid HTTP/1.1 frames. "
        "The payload is encrypted using ChaCha20-Poly1305."
    )
    pdf.add_image_centered('docs/images/packet.png', width=160)
    
    # 6. Security Analysis
    pdf.chapter_title(6, 'Security Analysis')
    pdf.chapter_body(
        "Identity Hiding: The client's static public key is encrypted before being sent to the server.\n\n"
        "Forward Secrecy: Ephemeral keys are generated for every session. Compromise of long-term keys does not compromise past sessions.\n\n"
        "Replay Protection: The server maintains a sliding window of seen nonces to prevent replay attacks."
    )

    # Save
    output_path = "Obsidian_Sovereign_Whitepaper.pdf"
    pdf.output(output_path)
    print(f"✅ PDF generated successfully: {output_path}")

if __name__ == "__main__":
    # Ensure docs/images exists
    os.makedirs('docs/images', exist_ok=True)
    create_pdf()
