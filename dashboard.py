import sqlite3
import json
import html
import os
from config import DB_FILE

def generate_dashboard():
    if not os.path.exists(DB_FILE):
        print("Database not found. Start main.py first.")
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT timestamp, attacker_ip, target_port, detected_service, country, isp, payload_received FROM incidents ORDER BY id DESC LIMIT 50")
    incidents = cursor.fetchall()
    
    cursor.execute("SELECT detected_service, COUNT(*) FROM incidents GROUP BY detected_service")
    services_data = cursor.fetchall()
    
    cursor.execute("SELECT country, COUNT(*) FROM incidents GROUP BY country")
    countries_data = cursor.fetchall()
    
    conn.close()

    labels_services = [row[0] for row in services_data]
    counts_services = [row[1] for row in services_data]
    
    labels_countries = [row[0] for row in countries_data]
    counts_countries = [row[1] for row in countries_data]

    table_rows = ""
    for row in incidents:
        ts = html.escape(str(row[0]))
        ip = html.escape(str(row[1]))
        port = html.escape(str(row[2]))
        service = html.escape(str(row[3]))
        country = html.escape(str(row[4]))
        isp = html.escape(str(row[5]))
        payload = html.escape(str(row[6]))

        table_rows += f"""
        <tr class="border-b border-gray-800 hover:bg-gray-800/50">
            <td class="p-3 text-gray-400 text-sm">{ts}</td>
            <td class="p-3 font-mono text-cyan-400">{ip}</td>
            <td class="p-3 font-mono">{port}</td>
            <td class="p-3"><span class="px-2 py-1 rounded text-xs bg-red-950/50 text-red-400 border border-red-900/30">{service}</span></td>
            <td class="p-3 text-gray-300">{country}</td>
            <td class="p-3 text-gray-500 text-sm">{isp}</td>
            <td class="p-3 font-mono text-xs text-yellow-500 max-w-xs truncate" title="{payload}">{payload}</td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SHADOW-TRAP Security Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body class="bg-[#0a0a0c] text-gray-100 min-h-screen p-6">
        <div class="max-w-7xl mx-auto space-y-6">
            <div class="flex justify-between items-center border-b border-gray-800 pb-4">
                <div>
                    <h1 class="text-3xl font-extrabold tracking-wider text-cyan-500">SHADOW-TRAP 🪤</h1>
                    <p class="text-gray-400 text-sm">Real-Time Threat Intelligence</p>
                </div>
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="bg-[#121216] border border-gray-800 rounded-lg p-6">
                    <h3 class="text-lg font-bold mb-4 text-cyan-400">Attack Vectors by Service</h3>
                    <div class="h-64 flex justify-center">
                        <canvas id="servicesChart"></canvas>
                    </div>
                </div>
                <div class="bg-[#121216] border border-gray-800 rounded-lg p-6">
                    <h3 class="text-lg font-bold mb-4 text-cyan-400">Attacker Origins (Geographical)</h3>
                    <div class="h-64 flex justify-center">
                        <canvas id="countriesChart"></canvas>
                    </div>
                </div>
            </div>

            <div class="bg-[#121216] border border-gray-800 rounded-lg p-6">
                <h3 class="text-lg font-bold mb-4 text-cyan-400">Recent Incidents (Last 50)</h3>
                <div class="overflow-x-auto">
                    <table class="w-full text-left border-collapse">
                        <thead>
                            <tr class="border-b border-gray-800 text-gray-400 font-semibold">
                                <th class="p-3">Timestamp</th>
                                <th class="p-3">Attacker IP</th>
                                <th class="p-3">Port</th>
                                <th class="p-3">Service</th>
                                <th class="p-3">Country</th>
                                <th class="p-3">ISP</th>
                                <th class="p-3">Captured Payload</th>
                            </tr>
                        </thead>
                        <tbody>
                            {table_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <script>
            new Chart(document.getElementById('servicesChart'), {{
                type: 'doughnut',
                data: {{
                    labels: {json.dumps(labels_services)},
                    datasets: [{{
                        data: {json.dumps(counts_services)},
                        backgroundColor: ['#06b6d4', '#ef4444', '#f59e0b', '#10b981', '#8b5cf6'],
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{ position: 'bottom', labels: {{ color: '#9ca3af' }} }}
                    }}
                }}
            }});

            new Chart(document.getElementById('countriesChart'), {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(labels_countries)},
                    datasets: [{{
                        data: {json.dumps(counts_countries)},
                        backgroundColor: '#06b6d4',
                        borderRadius: 4
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{ display: false }}
                    }},
                    scales: {{
                        x: {{ ticks: {{ color: '#9ca3af' }}, grid: {{ color: '#1f2937' }} }},
                        y: {{ ticks: {{ color: '#9ca3af' }}, grid: {{ color: '#1f2937' }} }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    """
    
    with open("dashboard.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    print("Success: dashboard.html generated.")

if __name__ == "__main__":
    generate_dashboard()