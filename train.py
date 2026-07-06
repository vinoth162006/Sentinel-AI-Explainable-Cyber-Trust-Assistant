import json
import math
import os
import random
from ml_classifier import classifier, SENSITIVE_KEYWORDS, SUSPICIOUS_TLDS

# Seed for reproducibility
random.seed(42)

def generate_mock_datasets() -> tuple[list[str], list[int]]:
    """
    Generates a balanced dataset of safe (0) and phishing (1) URLs.
    """
    urls = []
    labels = []

    # 1. Safe URLs (Label: 0)
    safe_domains = [
        "google.com", "github.com", "microsoft.com", "wikipedia.org", "amazon.com", 
        "apple.com", "youtube.com", "stackoverflow.com", "linkedin.com", "netflix.com",
        "medium.com", "reddit.com", "nytimes.com", "cnn.com", "twitter.com", "zoom.us",
        "gitlab.com", "bitbucket.org", "adobe.com", "cloudflare.com"
    ]
    safe_paths = ["", "/index.html", "/about", "/contact", "/search", "/docs", "/faq", "/profile", "/feed"]
    
    for _ in range(500):
        domain = random.choice(safe_domains)
        path = random.choice(safe_paths)
        sub = "www" if random.random() > 0.5 else ""
        domain_str = f"{sub}.{domain}" if sub else domain
        url = f"https://{domain_str}{path}"
        if random.random() > 0.7:
            url += f"?q={random.randint(100, 999)}&user={random.choice(['alice', 'bob', 'charlie'])}"
        urls.append(url)
        labels.append(0)

    # 2. Phishing/Suspicious URLs (Label: 1)
    suspicious_domains = [
        "login-secure-chase-update", "verification-portal-netflix", "paypal-security-account",
        "free-giftcard-deals", "update-bankofamerica-login", "appleid-support-verify",
        "cryptowallet-key-recovery", "signin-microsoft-office365", "netflix-members-activation"
    ]
    phish_tlds = SUSPICIOUS_TLDS + [".com", ".net", ".org"]
    phish_paths = ["/login", "/verify", "/update", "/signin", "/secure-portal", "/account/settings/update", "/webscr"]
    
    for _ in range(500):
        base = random.choice(suspicious_domains)
        tld = random.choice(phish_tlds)
        
        if random.random() > 0.3:
            host = f"{base}{tld}"
        else:
            host = f"{base}-{random.randint(10, 99)}{tld}"
            
        if random.random() > 0.5:
            host = f"secure.verification.update.{host}"
            
        protocol = "http" if random.random() > 0.6 else "https"
        path = random.choice(phish_paths)
        
        url = f"{protocol}://{host}{path}"
        
        if random.random() > 0.5:
            keyword = random.choice(SENSITIVE_KEYWORDS)
            url += f"?{keyword}=true"
        if random.random() > 0.8:
            url = f"{url.split('://')[0]}://trusted-site.com@{url.split('://')[1]}"
            
        urls.append(url)
        labels.append(1)
        
    return urls, labels

def train_pure_python():
    print("=" * 60)
    print("STARTING PURE-PYTHON ML MODEL TRAINING")
    print("=" * 60)
    
    urls, labels = generate_mock_datasets()
    print(f"Dataset generated: {len(urls)} URLs ({labels.count(0)} safe, {labels.count(1)} phishing)")
    
    # Feature extraction
    print("Extracting features...")
    X = [classifier.extract_features(url) for url in urls]
    
    # Feature Scaling: Simple Min-Max normalization for better gradient descent convergence
    # We will compute min and max for numerical features: url_length and hostname_length
    # The rest are already binary counts or small numbers.
    max_url_len = max(x["url_length"] for x in X) or 1.0
    max_host_len = max(x["hostname_length"] for x in X) or 1.0
    
    # Let's normalize url_length and hostname_length inside the feature dicts to [0, 1] range
    for x in X:
        x["url_length"] /= max_url_len
        x["hostname_length"] /= max_host_len

    # Train/Test Split (80% Train, 20% Test)
    indices = list(range(len(X)))
    random.shuffle(indices)
    
    split = int(0.8 * len(X))
    train_idx = indices[:split]
    test_idx = indices[split:]
    
    X_train = [X[i] for i in train_idx]
    y_train = [labels[i] for i in train_idx]
    
    X_test = [X[i] for i in test_idx]
    y_test = [labels[i] for i in test_idx]
    
    # Initialize parameters
    weights = {name: 0.0 for name in classifier.feature_names}
    bias = 0.0
    lr = 0.5  # Learning rate
    epochs = 1200
    
    print(f"Training Logistic Regression over {epochs} epochs...")
    n_train = len(X_train)
    
    for epoch in range(epochs):
        dw = {name: 0.0 for name in classifier.feature_names}
        db = 0.0
        total_loss = 0.0
        
        # Batch gradient descent
        for i in range(n_train):
            xi = X_train[i]
            yi = y_train[i]
            
            # Predict probability
            z = bias
            for name in classifier.feature_names:
                z += weights[name] * xi[name]
                
            # Sigmoid
            prob = 1.0 / (1.0 + math.exp(-max(-20, min(20, z))))
            
            # Binary Cross Entropy Loss
            p_clipped = max(1e-15, min(1.0 - 1e-15, prob))
            total_loss += - (yi * math.log(p_clipped) + (1.0 - yi) * math.log(1.0 - p_clipped))
            
            # Gradients
            error = prob - yi
            for name in classifier.feature_names:
                dw[name] += error * xi[name]
            db += error
            
        # Update weights and bias
        for name in classifier.feature_names:
            weights[name] -= lr * (dw[name] / n_train)
        bias -= lr * (db / n_train)
        
        # Log loss
        if epoch % 200 == 0:
            print(f"  Epoch {epoch:4d} | Average Loss: {total_loss / n_train:.4f}")
            
    # Evaluation
    print("\nEvaluating model on test set...")
    y_pred = []
    for xi in X_test:
        z = bias
        for name in classifier.feature_names:
            z += weights[name] * xi[name]
        prob = 1.0 / (1.0 + math.exp(-max(-20, min(20, z))))
        y_pred.append(1 if prob > 0.5 else 0)
        
    # Metrics
    tp = sum(1 for i in range(len(y_test)) if y_test[i] == 1 and y_pred[i] == 1)
    tn = sum(1 for i in range(len(y_test)) if y_test[i] == 0 and y_pred[i] == 0)
    fp = sum(1 for i in range(len(y_test)) if y_test[i] == 0 and y_pred[i] == 1)
    fn = sum(1 for i in range(len(y_test)) if y_test[i] == 1 and y_pred[i] == 0)
    
    accuracy = (tp + tn) / len(y_test)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print("-" * 40)
    print("TEST METRICS SUMMARY:")
    print(f"Accuracy:  {accuracy*100:.2f}%")
    print(f"Precision: {precision*100:.2f}%")
    print(f"Recall:    {recall*100:.2f}%")
    print(f"F1 Score:  {f1:.4f}")
    print("-" * 40)
    
    # Store weights back, correcting back for the non-normalized url/host lengths
    # by dividing the respective weights by the normalization factors!
    # This lets us use raw, un-normalized feature counts during inference!
    weights["url_length"] /= max_url_len
    weights["hostname_length"] /= max_host_len
    
    # Save the parameters
    model_output_path = os.path.join(os.path.dirname(__file__), "phishing_model.json")
    model_data = {
        "weights": weights,
        "bias": bias,
        "feature_names": classifier.feature_names
    }
    with open(model_output_path, "w") as f:
        json.dump(model_data, f, indent=2)
    print(f"Saved trained parameters to {model_output_path}")

if __name__ == "__main__":
    train_pure_python()
