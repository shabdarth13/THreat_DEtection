from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
import torch
import os


class PhishingDetector:
    def __init__(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))

        model_dir = os.path.join(
            base_dir,
            "..",
            "models",
            "bert_spam_classifier"
        )

        model_dir = os.path.abspath(model_dir)

        if not os.path.exists(model_dir):
            raise FileNotFoundError(f"Model directory not found: {model_dir}")

        print("Loading phishing model from:", model_dir)

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        self.tokenizer = DistilBertTokenizerFast.from_pretrained(model_dir)
        self.model = DistilBertForSequenceClassification.from_pretrained(model_dir)

        self.model.to(self.device)
        self.model.eval()

    def detect(self, email_text):
        if not email_text or not email_text.strip():
            return {
                "prediction": "Invalid Input",
                "confidence": 0
            }

        inputs = self.tokenizer(
            email_text,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512
        )

        inputs = {
            key: value.to(self.device)
            for key, value in inputs.items()
        }

        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.nn.functional.softmax(outputs.logits, dim=1)

            predicted_class = torch.argmax(probs, dim=1).item()
            confidence = probs[0][predicted_class].item()

        return {
            "prediction": "Phishing" if predicted_class == 1 else "Not Phishing",
            "confidence": round(confidence * 100, 2)
        }