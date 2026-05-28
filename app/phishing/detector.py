from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification
)

import torch
import os


class PhishingDetector:

    def __init__(self):

        try:

            BASE_DIR = os.path.dirname(os.path.abspath(__file__))

            model_dir = os.path.abspath(
                os.path.join(
                    BASE_DIR,
                    "..",
                    "models",
                    "bert_spam_classifier"
                )
            )

            print(f"Loading phishing model from: {model_dir}")

            if not os.path.exists(model_dir):
                raise FileNotFoundError(
                    f"Model directory not found: {model_dir}"
                )

            self.tokenizer = DistilBertTokenizerFast.from_pretrained(
                model_dir
            )

            self.model = DistilBertForSequenceClassification.from_pretrained(
                model_dir
            )

            self.model.eval()

            print("Phishing model loaded successfully.")

        except Exception as e:

            print(f"ERROR LOADING PHISHING MODEL: {str(e)}")

            raise e

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

        with torch.no_grad():

            outputs = self.model(**inputs)

            probs = torch.nn.functional.softmax(
                outputs.logits,
                dim=1
            )

            predicted_class = torch.argmax(probs).item()

            confidence = float(
                probs[0][predicted_class]
            ) * 100

        return {
            "prediction": (
                "Phishing"
                if predicted_class == 1
                else "Not Phishing"
            ),
            "confidence": round(confidence, 2)
        }