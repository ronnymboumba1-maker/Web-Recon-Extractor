# 1. Créer un dossier
mkdir -p ~/Programs/Web-Extractor && cd ~/Programs/Web-Extractor

# 2. Venv
python3 -m venv venv
source venv/bin/activate

# 3. Dépendances
pip install -r requirements.txt
pip install flask pyjwt  # pour le labo

# 4. Fichiers
# → copie web_extractor.py
# → copie lab_vulnerable.py

# 5. Terminal 1
python3 lab_vulnerable.py

# 6. Terminal 2 (dans le même venv)
python3 web_extractor.py http://localhost:5000 --phases all