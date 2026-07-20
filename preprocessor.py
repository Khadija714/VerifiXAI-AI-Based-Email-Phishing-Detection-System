import re
import nltk
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer

# Download NLTK data (first time only)
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('punkt_tab')

stemmer = PorterStemmer()
stop_words = set(stopwords.words('english'))

def preprocess_text(text):
    """Clean, tokenize, remove stopwords, stem a single text"""
    if not isinstance(text, str):
        return ""
    text = text.lower()
    text = re.sub(r'<.*?>', '', text)          # remove HTML tags
    text = re.sub(r'http\S+|www\S+|https\S+', '', text)  # remove URLs
    text = re.sub(r'\S+@\S+', '', text)        # remove emails
    text = re.sub(r'[^a-zA-Z\s]', '', text)    # keep only letters and spaces
    tokens = nltk.word_tokenize(text)
    tokens = [stemmer.stem(token) for token in tokens 
              if token not in stop_words and len(token) > 2]
    return ' '.join(tokens)

def preprocess_dataframe(df, text_column='text_combined'):
    """Apply preprocess_text to a column of DataFrame and add new column 'processed_text'"""
    df['processed_text'] = df[text_column].astype(str).apply(preprocess_text)
    return df