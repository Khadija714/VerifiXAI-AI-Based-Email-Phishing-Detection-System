import shap
import numpy as np
import pandas as pd
from preprocessor import preprocess_text

class SHAPExplainer:
    def __init__(self, model, vectorizer, background_texts=None, background_size=100):
        self.model = model
        self.vectorizer = vectorizer
        self.explainer = None
        self.background_size = background_size
        self._init_explainer(background_texts)
    
    def _init_explainer(self, background_texts):
        """Initialize KernelExplainer with a background sample (use smaller background)"""
        try:
            # Agar background texts nahi diye, to ek small dummy sample use karo
            if background_texts is None:
                # Sirf 2-3 dummy examples, taake SHAP slow na ho
                background_texts = [
                    "This is a normal email for meeting.",
                    "Hello team, please find attached report.",
                    "Your account has been updated successfully."
                ]
            
            # Preprocess background (only take first few to keep fast)
            bg_processed = [preprocess_text(t) for t in background_texts[:self.background_size]]
            bg_features = self.vectorizer.transform(bg_processed).toarray()
            
            # Prediction function for SHAP (must accept dense or sparse)
            def predict_fn(x):
                # x could be dense or sparse; convert to sparse if needed
                if not isinstance(x, np.ndarray):
                    x = np.array(x)
                return self.model.predict_proba(x)[:, 1]
            
            # Use KernelExplainer with smaller background to avoid memory issues
            # Important: SHAP can be very slow with 5000 features; we'll limit features later
            self.explainer = shap.KernelExplainer(predict_fn, bg_features)
            print("SHAP explainer initialized successfully.")
        except Exception as e:
            print(f"SHAP init failed: {e}")
            self.explainer = None
    
    def explain_email(self, email_text, top_n=5):
        """Explain why email is phishing or safe"""
        if self.explainer is None:
            return {"error": "SHAP not available", "factors": []}
        
        try:
            processed = preprocess_text(email_text)
            feature_vec = self.vectorizer.transform([processed]).toarray()
            
            # SHAP values compute (nsamples should be small for speed)
            shap_values = self.explainer.shap_values(feature_vec, nsamples=50)
            # shap_values shape: (n_samples, n_features) for binary classification
            # For single sample, shap_values[0] is array of shape (n_features,)
            if len(shap_values.shape) == 3:
                shap_vals = shap_values[0][0]  # for multi-output case
            else:
                shap_vals = shap_values[0]
            
            # Get top features
            feature_names = self.vectorizer.get_feature_names_out()
            abs_vals = np.abs(shap_vals)
            top_indices = np.argsort(abs_vals)[-top_n:][::-1]
            
            factors = []
            for idx in top_indices:
                if abs_vals[idx] > 0.005:  # low threshold to show some features
                    impact = "positive" if shap_vals[idx] > 0 else "negative"
                    factors.append({
                        "feature": feature_names[idx],
                        "shap_value": float(shap_vals[idx]),
                        "impact": impact,
                        "explanation": f"Word '{feature_names[idx]}' contributed {'to phishing' if shap_vals[idx] > 0 else 'to safe'} with strength {abs_vals[idx]:.3f}"
                    })
            return {"factors": factors}
        except Exception as e:
            print(f"Explanation failed: {e}")
            return {"error": str(e), "factors": []}