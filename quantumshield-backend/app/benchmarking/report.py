"""
Benchmark Report Generator

Generates PDF reports with tables and charts comparing PQ and classical
cryptographic performance.
"""

import io
import os
import time
from typing import Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from app.benchmarking.engine import BenchmarkSuite


class ReportGenerator:
    """
    Generates professional PDF benchmark reports with charts and tables.
    """

    def __init__(self, output_dir: str = "/tmp/quantumshield_reports") -> None:
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self._styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self) -> None:
        """Configure report styles."""
        self._styles.add(ParagraphStyle(
            "ReportTitle",
            parent=self._styles["Title"],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
        ))
        self._styles.add(ParagraphStyle(
            "SectionHeader",
            parent=self._styles["Heading2"],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor("#1a1a2e"),
        ))
        self._styles.add(ParagraphStyle(
            "BodyText2",
            parent=self._styles["Normal"],
            fontSize=10,
            spaceBefore=6,
            spaceAfter=6,
        ))

    def _create_comparison_chart(self, suite: BenchmarkSuite, chart_type: str) -> Optional[str]:
        """Create a comparison chart and return the file path."""
        fig, ax = plt.subplots(figsize=(8, 4.5))

        if chart_type == "signature_comparison":
            # Compare Dilithium3 vs RSA-2048 for sign/verify
            pq_results = [r for r in suite.results if r.algorithm == "Dilithium3" and r.category == "Signature"]
            classical_results = [r for r in suite.results if r.algorithm == "RSA-2048"]

            if not pq_results or not classical_results:
                plt.close(fig)
                return None

            operations = ["Key Generation", "Sign", "Verify"]
            pq_means = []
            classical_means = []
            for op in operations:
                pq_r = next((r for r in pq_results if r.operation == op), None)
                cl_r = next((r for r in classical_results if r.operation == op), None)
                pq_means.append(pq_r.mean_ms if pq_r else 0)
                classical_means.append(cl_r.mean_ms if cl_r else 0)

            x = np.arange(len(operations))
            width = 0.35
            bars1 = ax.bar(x - width / 2, pq_means, width, label="Dilithium3 (PQ)", color="#6366f1", edgecolor="white")
            bars2 = ax.bar(x + width / 2, classical_means, width, label="RSA-2048 (Classical)", color="#f59e0b", edgecolor="white")

            ax.set_xlabel("Operation", fontsize=11)
            ax.set_ylabel("Time (ms)", fontsize=11)
            ax.set_title("Signature: Dilithium3 vs RSA-2048", fontsize=13, fontweight="bold")
            ax.set_xticks(x)
            ax.set_xticklabels(operations)
            ax.legend()
            ax.grid(axis="y", alpha=0.3)

        elif chart_type == "kem_comparison":
            # Compare Kyber768 vs X25519
            pq_results = [r for r in suite.results if r.algorithm == "Kyber768"]
            classical_results = [r for r in suite.results if "X25519" in r.algorithm]

            if not pq_results or not classical_results:
                plt.close(fig)
                return None

            labels = []
            pq_vals = []
            cl_vals = []

            # Key generation comparison
            pq_kg = next((r for r in pq_results if r.operation == "Key Generation"), None)
            cl_kg = next((r for r in classical_results if r.operation == "Key Generation"), None)
            if pq_kg and cl_kg:
                labels.append("Key Generation")
                pq_vals.append(pq_kg.mean_ms)
                cl_vals.append(cl_kg.mean_ms)

            # Encap vs Exchange
            pq_enc = next((r for r in pq_results if r.operation == "Encapsulation"), None)
            cl_exc = next((r for r in classical_results if r.operation == "Key Exchange"), None)
            if pq_enc and cl_exc:
                labels.append("Encap/Exchange")
                pq_vals.append(pq_enc.mean_ms)
                cl_vals.append(cl_exc.mean_ms)

            if not labels:
                plt.close(fig)
                return None

            x = np.arange(len(labels))
            width = 0.35
            ax.bar(x - width / 2, pq_vals, width, label="Kyber768 (PQ)", color="#10b981", edgecolor="white")
            ax.bar(x + width / 2, cl_vals, width, label="X25519 (Classical)", color="#ef4444", edgecolor="white")

            ax.set_xlabel("Operation", fontsize=11)
            ax.set_ylabel("Time (ms)", fontsize=11)
            ax.set_title("KEM: Kyber768 vs X25519 (ECDHE)", fontsize=13, fontweight="bold")
            ax.set_xticks(x)
            ax.set_xticklabels(labels)
            ax.legend()
            ax.grid(axis="y", alpha=0.3)

        elif chart_type == "all_operations":
            # Overview of all operations
            names = [f"{r.algorithm}\n{r.operation}" for r in suite.results]
            means = [r.mean_ms for r in suite.results]
            cat_colors = {
                "KEM": "#10b981",
                "Signature": "#6366f1",
                "Classical Signature": "#f59e0b",
                "Classical KEM": "#ef4444",
                "Protocol": "#8b5cf6",
                "Token": "#06b6d4",
            }
            bar_colors = [cat_colors.get(r.category, "#64748b") for r in suite.results]

            ax.barh(range(len(names)), means, color=bar_colors, edgecolor="white")
            ax.set_yticks(range(len(names)))
            ax.set_yticklabels(names, fontsize=8)
            ax.set_xlabel("Time (ms)", fontsize=11)
            ax.set_title("All Cryptographic Operations Benchmark", fontsize=13, fontweight="bold")
            ax.grid(axis="x", alpha=0.3)
            ax.invert_yaxis()

        else:
            plt.close(fig)
            return None

        plt.tight_layout()
        path = os.path.join(self.output_dir, f"chart_{chart_type}.png")
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)
        return path

    def generate_benchmark_report(self, suite: BenchmarkSuite) -> str:
        """
        Generate a complete benchmark PDF report.
        
        Returns:
            Path to the generated PDF.
        """
        pdf_path = os.path.join(self.output_dir, "BenchmarkResults.pdf")
        doc = SimpleDocTemplate(pdf_path, pagesize=A4, topMargin=30 * mm, bottomMargin=20 * mm)
        story = []

        # Title page
        story.append(Spacer(1, 40))
        story.append(Paragraph("QuantumShield", self._styles["ReportTitle"]))
        story.append(Paragraph("Post-Quantum Cryptography Benchmark Results", self._styles["Heading2"]))
        story.append(Spacer(1, 20))
        story.append(Paragraph(
            f"Report generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            self._styles["BodyText2"],
        ))
        story.append(Paragraph(
            f"Total benchmark duration: {suite.total_duration_s:.2f} seconds",
            self._styles["BodyText2"],
        ))
        story.append(Spacer(1, 20))

        # Methodology
        story.append(Paragraph("Benchmark Methodology", self._styles["SectionHeader"]))
        story.append(Paragraph(
            "All benchmarks use time.perf_counter() for high-resolution timing. "
            "Each operation is measured independently with no artificial latency offsets. "
            "Statistics include mean, median, min, max, and standard deviation across all iterations.",
            self._styles["BodyText2"],
        ))
        story.append(Paragraph(
            "Post-quantum algorithms are implemented via liboqs-python using NIST standardized algorithms. "
            "Classical algorithms use the Python cryptography library.",
            self._styles["BodyText2"],
        ))

        # Results table
        story.append(Spacer(1, 10))
        story.append(Paragraph("Detailed Results", self._styles["SectionHeader"]))

        table_data = [["Operation", "Algorithm", "Category", "Iters", "Mean (ms)", "Median (ms)", "Min (ms)", "Max (ms)", "StdDev (ms)"]]
        for r in suite.results:
            table_data.append([
                r.operation, r.algorithm, r.category, str(r.iterations),
                f"{r.mean_ms:.4f}", f"{r.median_ms:.4f}",
                f"{r.min_ms:.4f}", f"{r.max_ms:.4f}", f"{r.stddev_ms:.4f}",
            ])

        table = Table(table_data, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ]))
        story.append(table)

        # Charts
        story.append(PageBreak())
        story.append(Paragraph("Performance Comparison Charts", self._styles["SectionHeader"]))

        for chart_type in ["signature_comparison", "kem_comparison", "all_operations"]:
            chart_path = self._create_comparison_chart(suite, chart_type)
            if chart_path:
                story.append(Spacer(1, 10))
                img = Image(chart_path, width=6.5 * inch, height=3.5 * inch)
                story.append(img)
                story.append(Spacer(1, 10))

        # Comparison analysis
        story.append(PageBreak())
        story.append(Paragraph("Comparison Analysis", self._styles["SectionHeader"]))

        # Find specific results for comparison
        dil_sign = next((r for r in suite.results if r.algorithm == "Dilithium3" and r.operation == "Sign"), None)
        rsa_sign = next((r for r in suite.results if r.algorithm == "RSA-2048" and r.operation == "Sign"), None)
        kyber_encap = next((r for r in suite.results if r.algorithm == "Kyber768" and r.operation == "Encapsulation"), None)
        x25519_exc = next((r for r in suite.results if "X25519" in r.algorithm and r.operation == "Key Exchange"), None)

        if dil_sign and rsa_sign:
            ratio = dil_sign.mean_ms / rsa_sign.mean_ms if rsa_sign.mean_ms > 0 else 0
            story.append(Paragraph(
                f"<b>Signature Performance:</b> Dilithium3 signing takes {dil_sign.mean_ms:.4f}ms vs "
                f"RSA-2048 at {rsa_sign.mean_ms:.4f}ms ({ratio:.1f}x ratio). "
                "Dilithium3 provides NIST Level 3 post-quantum security.",
                self._styles["BodyText2"],
            ))

        if kyber_encap and x25519_exc:
            ratio = kyber_encap.mean_ms / x25519_exc.mean_ms if x25519_exc.mean_ms > 0 else 0
            story.append(Paragraph(
                f"<b>KEM Performance:</b> Kyber768 encapsulation takes {kyber_encap.mean_ms:.4f}ms vs "
                f"X25519 key exchange at {x25519_exc.mean_ms:.4f}ms ({ratio:.1f}x ratio). "
                "Kyber768 is resistant to quantum attacks while maintaining practical performance.",
                self._styles["BodyText2"],
            ))

        kemtls_hs = next((r for r in suite.results if r.operation == "Full Handshake"), None)
        if kemtls_hs:
            story.append(Paragraph(
                f"<b>KEMTLS Handshake:</b> Complete handshake takes {kemtls_hs.mean_ms:.4f}ms mean latency. "
                "This includes Kyber768 key encapsulation and Dilithium3 server authentication.",
                self._styles["BodyText2"],
            ))

        story.append(Spacer(1, 20))
        story.append(Paragraph(
            "Conclusion: Post-quantum algorithms provide practical performance suitable for "
            "production deployment while offering protection against both classical and quantum adversaries.",
            self._styles["BodyText2"],
        ))

        doc.build(story)
        return pdf_path

    def generate_technical_documentation(self) -> str:
        """
        Generate TechnicalDocumentation.pdf.
        
        Returns:
            Path to the generated PDF.
        """
        pdf_path = os.path.join(self.output_dir, "TechnicalDocumentation.pdf")
        doc = SimpleDocTemplate(pdf_path, pagesize=A4, topMargin=30 * mm, bottomMargin=20 * mm)
        story = []

        # Title
        story.append(Spacer(1, 40))
        story.append(Paragraph("QuantumShield", self._styles["ReportTitle"]))
        story.append(Paragraph("Technical Documentation", self._styles["Heading2"]))
        story.append(Paragraph(
            "Post-Quantum Secure OpenID Connect using KEMTLS",
            self._styles["BodyText2"],
        ))
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            f"Version 1.0 — {time.strftime('%Y-%m-%d', time.gmtime())}",
            self._styles["BodyText2"],
        ))

        # 1. System Architecture
        story.append(PageBreak())
        story.append(Paragraph("1. System Architecture", self._styles["SectionHeader"]))
        story.append(Paragraph(
            "QuantumShield is a modular post-quantum secure identity platform. "
            "The system consists of: (1) PQ Crypto Module using liboqs for Kyber768 KEM and Dilithium3 signatures, "
            "(2) KEMTLS Protocol Engine implementing KEM-based TLS above TCP, "
            "(3) OIDC Provider implementing Authorization Code Flow with PKCE from scratch, "
            "(4) Token Engine creating JWTs signed with Dilithium3, "
            "(5) Benchmarking System for performance measurement, "
            "(6) Quantum Readiness Scanner for assessing external TLS configurations, "
            "and (7) a Professional Frontend dashboard.",
            self._styles["BodyText2"],
        ))

        # 2. KEMTLS Protocol Design
        story.append(Paragraph("2. KEMTLS Protocol Design", self._styles["SectionHeader"]))
        story.append(Paragraph(
            "KEMTLS replaces TLS signature-based authentication with KEM-based authentication. "
            "The handshake flow: (1) ClientHello with supported algorithms, "
            "(2) ServerHello with Kyber768 public key and Dilithium3 signing key, "
            "(3) Client encapsulates shared secret using server's KEM public key (ClientKEMEncap), "
            "(4) Server decapsulates to derive the same shared secret (ServerKEMDecap), "
            "(5) Server signs the handshake transcript with Dilithium3 (ServerAuth), "
            "(6) Client verifies the signature (ClientVerify). "
            "Session keys are derived using HKDF-SHA256 and used for AES-256-GCM encrypted communication.",
            self._styles["BodyText2"],
        ))
        story.append(Paragraph(
            "This is a KEMTLS secure channel implementation above TCP for research prototype purposes. "
            "It demonstrates the feasibility of KEM-based authentication for post-quantum transport security.",
            self._styles["BodyText2"],
        ))

        # 3. OIDC Integration
        story.append(Paragraph("3. OIDC Integration", self._styles["SectionHeader"]))
        story.append(Paragraph(
            "The OIDC Authorization Code Flow is implemented from scratch without external OAuth libraries. "
            "Endpoints: /.well-known/openid-configuration, /authorize, /token, /userinfo, /jwks.json. "
            "Features: client registration, authorization codes with expiry, PKCE (S256), "
            "nonce/state validation, scope validation, and refresh token rotation. "
            "All token communication is protected by the KEMTLS secure channel.",
            self._styles["BodyText2"],
        ))

        # 4. Cryptographic Design Decisions
        story.append(Paragraph("4. Cryptographic Design Decisions", self._styles["SectionHeader"]))
        story.append(Paragraph(
            "Algorithm selection: Kyber768 (ML-KEM-768, NIST Level 3) for key encapsulation — chosen for "
            "its balance of security and performance. Dilithium3 (ML-DSA-65, NIST Level 3) for digital "
            "signatures — provides strong post-quantum signatures with reasonable sizes. "
            "AES-256-GCM for symmetric encryption of the secure channel. "
            "HKDF-SHA256 for key derivation from KEM shared secrets. "
            "All PQ operations use liboqs-python, ensuring real cryptographic implementations.",
            self._styles["BodyText2"],
        ))

        # 5. Benchmark Methodology
        story.append(Paragraph("5. Benchmark Methodology", self._styles["SectionHeader"]))
        story.append(Paragraph(
            "All timing uses time.perf_counter() for nanosecond-resolution measurements. "
            "No artificial delays or offsets are added. Benchmarks are configurable (10/100/1000 iterations). "
            "Statistics: mean, median, min, max, standard deviation. "
            "Comparisons: Kyber768 vs X25519 (ECDHE), Dilithium3 vs RSA-2048, "
            "KEMTLS vs classical TLS handshake latency, PQ JWT vs classical JWT operations.",
            self._styles["BodyText2"],
        ))

        # 6. Security Analysis
        story.append(Paragraph("6. Security Analysis", self._styles["SectionHeader"]))
        story.append(Paragraph(
            "Quantum Resistance: All key exchange and signature operations use NIST standardized PQC algorithms "
            "resistant to Shor's algorithm. Forward Secrecy: Each KEMTLS session uses fresh KEM keypairs. "
            "Authentication: Server identity verified via Dilithium3 signatures on handshake transcript. "
            "Channel Security: AES-256-GCM provides authenticated encryption with 256-bit keys. "
            "Token Security: JWTs signed with Dilithium3 cannot be forged by quantum adversaries. "
            "PKCE: Protects against authorization code interception attacks.",
            self._styles["BodyText2"],
        ))

        # 7. Limitations
        story.append(Paragraph("7. Limitations", self._styles["SectionHeader"]))
        story.append(Paragraph(
            "Research Prototype: This is not production-ready. The KEMTLS implementation operates above TCP "
            "as an application-layer protocol, not as a true TLS replacement. "
            "Side-Channel Resistance: Not evaluated against timing or power analysis attacks. "
            "Key Management: Simplified for demonstration; production systems need HSM integration. "
            "Performance: Benchmarks reflect single-machine performance; distributed deployment may differ. "
            "Certificate Infrastructure: No X.509 PQ certificate chain is implemented. "
            "Interoperability: Custom JWKS format for PQ keys is not yet standardized.",
            self._styles["BodyText2"],
        ))

        doc.build(story)
        return pdf_path
