import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import dns.resolver
import dns.exception

# Liste over typiske DNS record-typer
DNS_RECORD_TYPES = [
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "SOA",
    "SRV",
    "PTR",
    "CAA",
    "NAPTR",
    "ANY",
]


def append_output(text_widget, text):
    """Tilføj tekst til output-feltet og scroll ned."""
    text_widget.insert(tk.END, text + "\n")
    text_widget.see(tk.END)


def resolve_dns(name, record_type, text_widget, resolver):
    """Slår et navn op og skriver resultatet i text_widget."""
    name = name.strip()
    if not name:
        return

    append_output(text_widget, f"=== {name} ({record_type}) ===")

    try:
        if record_type == "ANY":
            answers = resolver.resolve(name, "ANY", lifetime=resolver.lifetime)
        else:
            answers = resolver.resolve(name, record_type, lifetime=resolver.lifetime)

        for rdata in answers:
            append_output(text_widget, f"  {rdata.to_text()}")

    except dns.resolver.NoAnswer:
        append_output(text_widget, "  [Ingen svar for denne type]")
    except dns.resolver.NXDOMAIN:
        append_output(text_widget, "  [Domænet findes ikke (NXDOMAIN)]")
    except dns.resolver.Timeout:
        append_output(text_widget, "  [Timeout på forespørgslen]")
    except dns.exception.DNSException as e:
        append_output(text_widget, f"  [DNS-fejl: {e}]")
    except Exception as e:
        append_output(text_widget, f"  [Ukendt fejl: {e}]")

    append_output(text_widget, "")  # Tom linje mellem navne


def on_single_lookup(entry_host, record_type_var, text_output, resolver):
    """Handler til knap: slå enkelt host op."""
    hostname = entry_host.get().strip()
    if not hostname:
        messagebox.showwarning("Manglende host", "Indtast et hostnavn/domæne først.")
        return

    record_type = record_type_var.get().strip().upper()
    if not record_type:
        messagebox.showwarning("Manglende type", "Vælg en DNS record-type.")
        return

    resolve_dns(hostname, record_type, text_output, resolver)


def on_file_lookup(record_type_var, text_output, resolver):
    """Handler til knap: vælg fil og slå alle hostnavne i filen op."""
    record_type = record_type_var.get().strip().upper()
    if not record_type:
        messagebox.showwarning("Manglende type", "Vælg en DNS record-type.")
        return

    file_path = filedialog.askopenfilename(
        title="Vælg fil med hostnavne",
        filetypes=[("Tekstfiler", "*.txt"), ("Alle filer", "*.*")]
    )
    if not file_path:
        return  # Bruger annullerede

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        messagebox.showerror("Fejl ved læsning af fil", str(e))
        return

    append_output(text_output, f"### Starter DNS-opslag fra fil: {file_path} ###\n")

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            # Ignorér tomme linjer og kommentarer
            continue
        resolve_dns(line, record_type, text_output, resolver)

    append_output(text_output, f"### Færdig med fil: {file_path} ###\n")


def on_clear_output(text_output):
    """Rydder output-feltet."""
    text_output.delete("1.0", tk.END)


def update_dns_servers(resolver, dns_var, text_widget):
    """Opdaterer hvilke DNS-servere der bruges til opslag."""
    servers = dns_var.get().strip()

    if not servers:
        messagebox.showwarning("DNS-servere mangler", "Indtast mindst én DNS-server.")
        return

    # Split på komma, fjern whitespace
    server_list = [s.strip() for s in servers.split(",") if s.strip()]

    if not server_list:
        messagebox.showwarning("DNS-servere mangler", "Indtast mindst én DNS-server.")
        return

    # Simpel validering (IPv4-format) – advarsel, men ikke hård fejl
    for s in server_list:
        parts = s.split(".")
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            append_output(text_widget, f"[Advarsel] '{s}' ligner ikke en klassisk IPv4-adresse.")

    resolver.nameservers = server_list
    append_output(text_widget, f"[Info] DNS-servere opdateret til: {', '.join(server_list)}\n")


def create_gui():
    root = tk.Tk()
    root.title("DNS Opslag")

    # --------- Resolver konfiguration ----------
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0       # sekunder pr. forsøg
    resolver.lifetime = 5.0      # maks samlet tid
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # standard – kan ændres i GUI'en

    # --------- Layout grundstruktur ----------
    main_frame = ttk.Frame(root, padding=10)
    main_frame.grid(row=0, column=0, sticky="nsew")

    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

    # --------- Linje 0: host + record-type + slå op ----------
    label_host = ttk.Label(main_frame, text="Host / domæne:")
    label_host.grid(row=0, column=0, sticky="w")

    entry_host = ttk.Entry(main_frame, width=40)
    entry_host.grid(row=0, column=1, sticky="ew", padx=5)

    label_type = ttk.Label(main_frame, text="Record-type:")
    label_type.grid(row=0, column=2, sticky="w", padx=(10, 0))

    record_type_var = tk.StringVar(value="A")
    combo_type = ttk.Combobox(
        main_frame,
        textvariable=record_type_var,
        values=DNS_RECORD_TYPES,
        state="readonly",
        width=8,
    )
    combo_type.grid(row=0, column=3, sticky="w")

    btn_lookup = ttk.Button(
        main_frame,
        text="Slå op",
        command=lambda: on_single_lookup(entry_host, record_type_var, text_output, resolver),
    )
    btn_lookup.grid(row=0, column=4, padx=(10, 0))

    # --------- Linje 1: fil-opslag + ryd output ----------
    btn_file = ttk.Button(
        main_frame,
        text="Slå op fra fil...",
        command=lambda: on_file_lookup(record_type_var, text_output, resolver),
    )
    btn_file.grid(row=1, column=1, sticky="w", pady=(10, 0))

    btn_clear = ttk.Button(
        main_frame,
        text="Ryd output",
        command=lambda: on_clear_output(text_output),
    )
    btn_clear.grid(row=1, column=2, sticky="w", pady=(10, 0))

    # --------- Linje 2: DNS-server(e) valg ----------
    label_dns = ttk.Label(main_frame, text="DNS-server(e):")
    label_dns.grid(row=2, column=0, sticky="w", pady=(10, 0))

    dns_var = tk.StringVar(value="8.8.8.8, 1.1.1.1")
    entry_dns = ttk.Entry(main_frame, textvariable=dns_var, width=40)
    entry_dns.grid(row=2, column=1, columnspan=2, sticky="ew", padx=5, pady=(10, 0))

    btn_set_dns = ttk.Button(
        main_frame,
        text="Brug disse DNS-servere",
        command=lambda: update_dns_servers(resolver, dns_var, text_output),
    )
    btn_set_dns.grid(row=2, column=3, columnspan=2, sticky="w", padx=(10, 0), pady=(10, 0))

    # --------- Linje 3: tekst-output + scrollbars ----------
    text_frame = ttk.Frame(main_frame)
    text_frame.grid(row=3, column=0, columnspan=5, sticky="nsew", pady=(10, 0))

    main_frame.rowconfigure(3, weight=1)
    main_frame.columnconfigure(1, weight=1)

    global text_output
    text_output = tk.Text(text_frame, wrap="none", height=20)
    text_output.grid(row=0, column=0, sticky="nsew")

    scrollbar_y = ttk.Scrollbar(text_frame, orient="vertical", command=text_output.yview)
    scrollbar_y.grid(row=0, column=1, sticky="ns")

    scrollbar_x = ttk.Scrollbar(text_frame, orient="horizontal", command=text_output.xview)
    scrollbar_x.grid(row=1, column=0, sticky="ew")

    text_output.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

    text_frame.rowconfigure(0, weight=1)
    text_frame.columnconfigure(0, weight=1)

    # --------- Linje 4: lille info-tekst ----------
    info_label = ttk.Label(
        main_frame,
        text=(
            "Tip: Filopslag bruger ét hostnavn per linje. Linjer der starter med # ignoreres.\n"
            "DNS-servere kan angives kommasepareret, f.eks. 8.8.8.8, 1.1.1.1"
        ),
        foreground="gray"
    )
    info_label.grid(row=4, column=0, columnspan=5, sticky="w", pady=(8, 0))

    return root


if __name__ == "__main__":
    app = create_gui()
    app.mainloop()
