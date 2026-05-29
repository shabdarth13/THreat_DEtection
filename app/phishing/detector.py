from transformers import pipeline


class PhishingDetector:
    def __init__(self):
        self.model_name = "shabdarth13/bert-spam-classifier"

        self.classifier = pipeline(
            "text-classification",
            model=self.model_name,
            tokenizer=self.model_name
        )

        print("Phishing model loaded from Hugging Face successfully.")

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

        if "1" in label or "phish" in label or "spam" in label:
            prediction = "Phishing"
        else:
            prediction = "Not Phishing"

        return {
            "prediction": prediction,
            "confidence": confidence,
            "raw_label": raw_label
        }