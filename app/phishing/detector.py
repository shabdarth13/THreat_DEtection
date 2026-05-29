from transformers import pipeline
import os


class PhishingDetector:
    def __init__(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))

        local_model_dir = os.path.abspath(
            os.path.join(base_dir, "..", "models", "bert_spam_classifier")
        )

        try:
            if os.path.exists(os.path.join(local_model_dir, "model.safetensors")):
                print("Loading local phishing model...")
                self.classifier = pipeline(
                    "text-classification",
                    model=local_model_dir,
                    tokenizer=local_model_dir
                )
            else:
                print("Local model not found. Loading Hugging Face phishing model...")
                self.classifier = pipeline(
                    "text-classification",
                    model="ealvaradob/bert-finetuned-phishing"
                )

            print("Phishing detector loaded successfully.")

        except Exception as e:
            raise RuntimeError(f"Failed to load phishing detector: {str(e)}")

    def detect(self, email_text):
        if not email_text or not email_text.strip():
            return {
                "prediction": "Invalid Input",
                "confidence": 0
            }

        result = self.classifier(email_text[:512])[0]

        raw_label = result["label"]
        label = raw_label.lower()
        confidence = round(result["score"] * 100, 2)

        if "phish" in label or "malicious" in label or label in ["label_1", "1"]:
            prediction = "Phishing"
        else:
            prediction = "Not Phishing"

        return {
            "prediction": prediction,
            "confidence": confidence,
            "raw_label": raw_label
        }