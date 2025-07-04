# app/phishing/detector.py

from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
import torch
import os

class PhishingDetector:
    def __init__(self):
       model_dir=r"C:\Users\acer\OneDrive\Desktop\threat-detection\app\models\bert_spam_classifier"
       self.tokenizer = DistilBertTokenizerFast.from_pretrained(model_dir)
       self.model = DistilBertForSequenceClassification.from_pretrained(model_dir)

    def detect(self, email_text):
        inputs = self.tokenizer(email_text, return_tensors="pt", truncation=True, padding=True, max_length=512)
        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=1)
            predicted_class = torch.argmax(probs).item()
            confidence = float(probs[0][predicted_class])
        
        return {
            "prediction": "Phishing" if predicted_class == 1 else "Not Phishing",
            "confidence": confidence
        }
