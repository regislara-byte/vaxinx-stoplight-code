from pathlib import Path

TEST_LAB = Path("test_lab")

SAMPLES = {
    "fake_virus_infect_replicate.exe": "SAFE VAXINX TEST SAMPLE ONLY.\nSimulates virus behavior.\n",
    "fake_trojan_free_game_patch.txt.vbs": "SAFE VAXINX TEST SAMPLE ONLY.\nSimulates Trojan disguise.\n",
    "fake_worm_network_share_replicate.js": "SAFE VAXINX TEST SAMPLE ONLY.\nSimulates worm behavior.\n",
    "fake_ransom_encrypt_locked_payment.txt": "SAFE VAXINX TEST SAMPLE ONLY.\nSimulates ransomware.\n",
    "fake_spyware_keylogger_password_token.ps1": "SAFE VAXINX TEST SAMPLE ONLY.\nSimulates spyware.\n",
    "fake_adware_popup_ads.zip": "SAFE VAXINX TEST SAMPLE ONLY.\nSimulates adware.\n",
    "fake_scareware_urgent_security-alert.bat": "SAFE VAXINX TEST SAMPLE ONLY.\nSimulates scareware.\n",
    "fake_backdoor_remote_shell.cmd": "SAFE VAXINX TEST SAMPLE ONLY.\nSimulates backdoor.\n",
    "fake_rootkit_stealth_kernel.dll": "SAFE VAXINX TEST SAMPLE ONLY.\nSimulates rootkit.\n",
    "green_normal_note.txt": "SAFE CLEAN FILE.\n",
    "yellow_password_note.txt": "Contains keyword password.\n",
    "human_error_fake_bank_login.txt.vbs": "SAFE TEST SAMPLE ONLY.\nSimulates phishing attachment.\n",
    "human_error_urgent_invoice.pdf.exe": "SAFE TEST SAMPLE ONLY.\nSimulates disguised executable.\n",
    "human_error_free_wifi_password.txt": "SAFE TEST SAMPLE ONLY.\nSimulates unsafe password sharing.\n",
     "human_error_update_required.bat": "SAFE TEST SAMPLE ONLY.\nSimulates fake update lure.\n",
}

def main():
    TEST_LAB.mkdir(exist_ok=True)

    for filename, content in SAMPLES.items():
        path = TEST_LAB / filename
        path.write_text(content, encoding="utf-8")
        print(f"Created: {path}")

    print("\n✅ Safe VAXINX test lab generated.")
    print("Next run:")
    print("python scanner.py")

if __name__ == "__main__":
    main()