import streamlit as st
import bcrypt
import os
import requests
from dotenv import load_dotenv
from azure.storage.blob import BlobServiceClient
import json
import uuid
from datetime import datetime
from authlib.integrations.requests_client import OAuth2Session
import logging
import re
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="RINGS & I - AI Ring Advisor", 
    page_icon="💍", 
    layout="centered",
    initial_sidebar_state="expanded",
    menu_items=None
)
import streamlit as st

# Apply CSS fix to all input components
st.markdown("""
    <style>
    /* Remove extra container border */
    div[data-baseweb="input"] {
        border: none !important;
        box-shadow: none !important;
    }

    /* Style the actual input field */
    input, textarea {
        border: 1px solid #ccc !important;
        border-radius: 6px !important;
        box-shadow: none !important;
        padding: 0.5rem !important;
        background-color: #f8f9fa !important;
    }

    input:focus, textarea:focus {
        outline: none !important;
        box-shadow: 0 0 0 2px #a3d2fc !important; /* optional glow */
        border: 1px solid #228be6 !important;
    }
    </style>
""", unsafe_allow_html=True)

# --- SESSION STATE INITIALIZATION ---
if "logged_in" not in st.session_state:
    st.session_state.update({
        "logged_in": False,
        "username": None,
        "email": None,
        "user_id": None,
        "oauth_provider": None,
        "show_register": False,
        "messages": [],
        "full_name": None,
        "show_auth": False,
        "temp_user": True,
        "initialized": False,
        "auth_tab": "login",
        "show_quick_prompts": True,
        "uploaded_file": None
    })

# --- CONFIGURATION ---
class Config:
    # Azure Storage Configuration
    AZURE_CONNECTION_STRING = "DefaultEndpointsProtocol=https;AccountName=botstorageai;AccountKey=JLxGrpJew2O1QXFG6HP5nP+oQdu8MtqVc5mC09/Z67Kq2qh+CnyH/4gZK5+6W4CIjw/G105NTAX++AStXmSbbA==;EndpointSuffix=core.windows.net"
    CONTAINER_NAME = "bot-data"
    GOOGLE_LOGO_URL = "https://cdn.shopify.com/s/files/1/0843/6917/8903/files/image.webp?v=1744437922"

    # OAuth Configuration
    GOOGLE_CLIENT_ID = "654156985064-vt48t8gj3qod98m4toivp6975lcdojom.apps.googleusercontent.com"
    GOOGLE_CLIENT_SECRET = "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"
    REDIRECT_URI = "http://localhost:8501"
    IMAGE_API_URL = "https://ringexpert-backend.azurewebsites.net/generate-image"
    # API Configuration
    CHAT_API_URL = "https://ringexpert-backend.azurewebsites.net/ask"
    BOT_AVATAR_URL = "https://i.imgur.com/JQ6W0nD.png"
    LOGO_URL = "https://ringsandi.com/wp-content/uploads/2023/11/ringsandi-logo.png"
    QUICK_PROMPTS = [
        "What is Ringsandi?",
        "Studio Location?",
        "What will I get different at RINGS & I?",
        "What is the main difference between 14K and 18K gold?",
        "What is the main difference between platinum and gold in terms of purity?"
    ]

# --- AZURE STORAGE SERVICE ---
class AzureStorage:
    def __init__(self):
        self._initialize_storage()
        
    def _initialize_storage(self):
        """Initialize and validate Azure Storage connection"""
        try:
            logger.info("Initializing Azure Storage connection")
            self.blob_service = BlobServiceClient.from_connection_string(Config.AZURE_CONNECTION_STRING)
            self.container = self.blob_service.get_container_client(Config.CONTAINER_NAME)
            
            if not self.container.exists():
                logger.info(f"Creating container: {Config.CONTAINER_NAME}")
                self.container.create_container()
                self._initialize_folder_structure()
                
            logger.info("Azure Storage initialized successfully")
            
        except Exception as e:
            logger.error(f"Storage initialization failed: {str(e)}")
            st.error("Failed to initialize storage system. Please contact support.")
            st.stop()
    
    def _initialize_folder_structure(self):
        """Create required directory structure"""
        try:
            self.upload_blob("users/.placeholder", "")
            self.upload_blob("chats/.placeholder", "")
            logger.info("Created storage folder structure")
        except Exception as e:
            logger.warning(f"Couldn't create folders: {str(e)}")
    
    def upload_blob(self, blob_name, data):
        """Secure blob upload with validation"""
        try:
            blob = self.container.get_blob_client(blob_name)
            if isinstance(data, (dict, list)):
                data = json.dumps(data, indent=2)
            blob.upload_blob(data, overwrite=True)
            return True
        except Exception as e:
            logger.error(f"Upload failed for {blob_name}: {str(e)}")
            return False
    
    def upload_file(self, blob_name, file_data, content_type=None):
        """Upload file data to blob storage"""
        try:
            blob = self.container.get_blob_client(blob_name)
            blob.upload_blob(file_data, overwrite=True, content_type=content_type)
            return True
        except Exception as e:
            logger.error(f"File upload failed for {blob_name}: {str(e)}")
            return False
    
    def download_blob(self, blob_name):
        """Secure blob download with validation"""
        try:
            blob = self.container.get_blob_client(blob_name)
            if blob.exists():
                return blob.download_blob().readall()
            return None
        except Exception as e:
            logger.error(f"Download failed for {blob_name}: {str(e)}")
            return None
    
    def blob_exists(self, blob_name):
        try:
            return self.container.get_blob_client(blob_name).exists()
        except Exception as e:
            logger.error(f"Existence check failed for {blob_name}: {str(e)}")
            return False
    
    def user_exists(self, email):
        return self.blob_exists(f"users/{email}.json")
    
    def create_user(self, email, password=None, username=None, provider=None, **kwargs):
        user_data = {
            "user_id": str(uuid.uuid4()),
            "email": email,
            "username": username or email.split('@')[0],
            "password": self._hash_password(password or "oauth_user"),
            "provider": provider,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": datetime.utcnow().isoformat(),
            **kwargs
        }
        
        if self.upload_blob(f"users/{email}.json", user_data):
            return user_data
        return None
    
    def get_user(self, email):
        data = self.download_blob(f"users/{email}.json")
        return json.loads(data) if data else None
    
    def authenticate_user(self, email, password):
        user = self.get_user(email)
        if user and self._check_password(password, user["password"]):
            return user
        return None
    
    def save_chat(self, user_id, messages):
        if messages:  # Only save if there are messages
            return self.upload_blob(f"chats/{user_id}.json", messages)
        return False
    
    def load_chat(self, user_id):
        data = self.download_blob(f"chats/{user_id}.json")
        return json.loads(data) if data else []
    
    def _hash_password(self, password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    def _check_password(self, input_password, hashed_password):
        try:
            return bcrypt.checkpw(input_password.encode(), hashed_password.encode())
        except:
            return False

# Initialize storage
storage = AzureStorage()

# --- OAUTH SERVICE ---
class OAuthService:
    @staticmethod
    def get_google_auth_url():
        client = OAuth2Session(
            Config.GOOGLE_CLIENT_ID,
            Config.GOOGLE_CLIENT_SECRET,
            redirect_uri=Config.REDIRECT_URI
        )
        return client.create_authorization_url(
            "https://accounts.google.com/o/oauth2/auth",
            scope="openid email profile",
            access_type="offline",
            prompt="consent",
            state="google"
        )[0]
    
    @staticmethod
    def handle_google_callback(code):
        try:
            client = OAuth2Session(
                Config.GOOGLE_CLIENT_ID,
                Config.GOOGLE_CLIENT_SECRET,
                redirect_uri=Config.REDIRECT_URI
            )
            
            token = client.fetch_token(
                "https://oauth2.googleapis.com/token",
                code=code,
                redirect_uri=Config.REDIRECT_URI
            )
            
            user_info = client.get("https://www.googleapis.com/oauth2/v3/userinfo").json()
            return user_info
        except Exception as e:
            logger.error(f"OAuth callback failed: {str(e)}")
            return None

# --- HELPER FUNCTIONS ---
def validate_email(email):
    """Validate email format using regex"""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password meets complexity requirements"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one number"
    if not any(char in "!@#$%^&*()-_=+" for char in password):
        return False, "Password must contain at least one special character"
    return True, ""

def process_uploaded_file(uploaded_file):
    """Process uploaded file and return base64 encoded string"""
    try:
        if uploaded_file is not None:
            file_bytes = uploaded_file.getvalue()
            return base64.b64encode(file_bytes).decode('utf-8')
        return None
    except Exception as e:
        logger.error(f"Error processing file: {str(e)}")
        return None

def handle_user_prompt(prompt, uploaded_file=None):
    """Handle user prompt and AI response"""
    st.session_state.messages.append({"role": "user", "content": prompt})
    
    # Add file info to message if uploaded
    if uploaded_file:
        file_icon = "📄" if "pdf" in uploaded_file.type else "🖼️"
        st.session_state.messages[-1]["file"] = {
            "name": uploaded_file.name,
            "type": uploaded_file.type,
            "icon": file_icon
        }
    
    st.session_state.show_quick_prompts = False
    
    with st.spinner(''):
        try:
            # Process file if uploaded
            file_data = None
            if uploaded_file:
                file_data = process_uploaded_file(uploaded_file)
            
            # Prepare payload for API
            payload = {
                "question": prompt,
                "file_data": file_data,
                "file_name": uploaded_file.name if uploaded_file else None,
                "file_type": uploaded_file.type if uploaded_file else None
            }
            
            # Determine which API endpoint to use
            if "generate" in prompt.lower() and "ring" in prompt.lower():
                response = requests.post(
                    Config.IMAGE_API_URL,
                    json={"prompt": prompt},
                    timeout=30
                )
                response.raise_for_status()
                image_url = response.json().get("image_url", "")
                
                if image_url and image_url.startswith("http"):
                    answer = f"Here's your AI-generated ring:\n\n![Generated Ring]({image_url})"
                else:
                    answer = "Sorry, the image could not be generated."
            else:
                response = requests.post(
                    Config.CHAT_API_URL,
                    json=payload,
                    timeout=15
                )
                answer = response.json().get("answer", "I couldn't process that request.")
                
        except Exception as e:
            logger.error(f"Error: {str(e)}")
            answer = "Sorry, I'm having trouble connecting to the service."
    
    st.session_state.messages.append({"role": "assistant", "content": answer})
    
    if st.session_state.logged_in:
        storage.save_chat(st.session_state.user_id, st.session_state.messages)
    
    st.session_state.uploaded_file = None
    st.rerun()

def complete_login(user_data):
    """Complete login process and set session state"""
    st.session_state.update({
        "logged_in": True,
        "user_id": user_data["user_id"],
        "email": user_data["email"],
        "username": user_data["username"],
        "full_name": user_data.get("full_name", user_data["username"]),
        "oauth_provider": user_data.get("provider"),
        "messages": storage.load_chat(user_data["user_id"]) or st.session_state.messages,
        "show_auth": False,
        "temp_user": False,
        "show_quick_prompts": True
    })
    
    # Update last login time
    try:
        user_data["last_login"] = datetime.utcnow().isoformat()
        storage.upload_blob(f"users/{user_data['email']}.json", user_data)
    except Exception as e:
        logger.error(f"Error updating last login: {str(e)}")
    
    st.rerun()

def logout():
    """Handle logout process"""
    if st.session_state.logged_in and st.session_state.user_id:
        storage.save_chat(st.session_state.user_id, st.session_state.messages)
    
    # Preserve messages for guest users
    temp_messages = st.session_state.messages if st.session_state.temp_user else []
    
    st.session_state.update({
        "logged_in": False,
        "user_id": None,
        "email": None,
        "username": None,
        "full_name": None,
        "oauth_provider": None,
        "show_auth": False,
        "temp_user": True,  # Reset to guest user
        "show_quick_prompts": True,
        "uploaded_file": None
    })
    
    # Restore messages for guest users
    st.session_state.messages = temp_messages
    st.rerun()

# --- AUTHENTICATION UI ---
def show_auth_ui():
    st.markdown("""
        <style>
            .welcome-header {
                text-align: center;
                margin-bottom: 5rem;
            }
            .logo-fixed {
                margin-top: 3px !important;
                padding-top: 0px !important;
            }
            .welcome-container {
                margin-top: 0 !important;
                padding-top: 0px !important;
            }
            .welcome-title {
                font-size: 32px;
                font-weight: 800;
                margin-bottom: 0.75rem;
                color: #000;
                letter-spacing: 0.5px;
                text-transform: uppercase;
            }
            .welcome-subtitle {
                color: #555;
                font-size: 18px;
                font-weight: 400;
                line-height: 1.5;
            }
            .stTextInput>div>div>input {
                border: 1px solid #ddd !important;
                border-radius: 8px !important;
                padding: 12px 16px !important;
                font-size: 15px;
                transition: all 0.3s ease;
            }
            .stTextInput>div>div>input:focus {
                border-color: #000 !important;
                box-shadow: 0 0 0 2px rgba(0,0,0,0.1) !important;
                outline: none;
            }
            .stTextInput>label {
                font-weight: 600;
                color: #333;
                margin-bottom: 8px;
            }
            .stButton>button {
                border-radius: 8px !important;
                padding: 12px 24px !important;
                font-weight: 600 !important;
                transition: all 0.3s ease !important;
            }
            .stButton>button:not(:disabled):hover {
                transform: translateY(-1px);
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
            }
        </style>
    """, unsafe_allow_html=True)

    st.markdown("""
        <div class="welcome-header">
            <div class="welcome-title">WELCOME TO RINGS & I!</div>
            <div class="welcome-subtitle">The RingExpert is here to help. Ask away!</div>
        </div>
    """, unsafe_allow_html=True)
    
    tabs = st.tabs(["Sign In", "Create Account"])
    
    with tabs[0]:
        show_login_form()
    
    with tabs[1]:
        show_register_form()

def show_login_form():
    """Login form with Forgot Password allowing password reset"""
    if st.session_state.get("show_forgot_password", False):
        st.markdown("### 🔐 Reset Your Password")

        with st.form("forgot_password_form"):
            reset_email = st.text_input("Registered Email", placeholder="you@example.com")
            new_password = st.text_input("New Password", type="password", placeholder="Create a new password")
            confirm_password = st.text_input("Confirm New Password", type="password")

            submit_btn = st.form_submit_button("Update Password", type="primary")

            if submit_btn:
                if not validate_email(reset_email):
                    st.error("Please enter a valid email address")
                elif not storage.user_exists(reset_email):
                    st.error("No account found with that email.")
                elif new_password != confirm_password:
                    st.error("Passwords do not match.")
                else:
                    is_valid, msg = validate_password(new_password)
                    if not is_valid:
                        st.error(msg)
                    else:
                        user_data = storage.get_user(reset_email)
                        user_data["password"] = storage._hash_password(new_password)
                        storage.upload_blob(f"users/{reset_email}.json", user_data)
                        st.success("✅ Password updated successfully! Please log in with your new password.")
                        st.session_state.show_forgot_password = False
                        st.rerun()

        if st.button("← Back to Login"):
            st.session_state.show_forgot_password = False
            st.rerun()

    else:
        with st.form(key="login_form"):
            email = st.text_input("Email Address", key="login_email", placeholder="Enter your email")
            password = st.text_input("Password", type="password", key="login_password", placeholder="Enter your password")

            # Forgot Password Link (below password field)
            col1, col2 = st.columns([2, 1])
            with col2:
                if st.form_submit_button("Forgot Password?", help="Reset your password", type="primary"):
                    st.session_state.show_forgot_password = True
                    st.rerun()

            login_btn = st.form_submit_button("Sign In", type="primary")

            if login_btn:
                if not email or not password:
                    st.error("Please enter both email and password")
                else:
                    user = storage.authenticate_user(email, password)
                    if user:
                        complete_login(user)
                    else:
                        st.error("Invalid credentials. Please try again.")

        # Add Google Sign-In Button
        st.markdown("""
        <style>
            .google-btn {
                display: flex;
                align-items: center;
                justify-content: center;
                background: white;
                color: #757575;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 10px;
                width: 100%;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.3s;
                margin-top: 10px;
            }
            .google-btn:hover {
                background: #f7f7f7;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }
            .google-logo {
                height: 18px;
                margin-right: 10px;
            }
            .divider {
                display: flex;
                align-items: center;
                margin: 15px 0;
                color: #777;
                font-size: 14px;
            }
            .divider::before, .divider::after {
                content: "";
                flex: 1;
                border-bottom: 1px solid #ddd;
            }
            .divider::before {
                margin-right: 10px;
            }
            .divider::after {
                margin-left: 10px;
            }
        </style>
        """, unsafe_allow_html=True)

        st.markdown('<div class="divider">OR</div>', unsafe_allow_html=True)
        
        google_auth_url = OAuthService.get_google_auth_url()
        st.markdown(
    f'<a href="{google_auth_url}" class="google-btn" target="_self">'
    f'<img src="{Config.GOOGLE_LOGO_URL}" class="google-logo">Sign in with Google</a>',
    unsafe_allow_html=True
)





def show_register_form():
    """Show only the registration form"""
    with st.form(key="register_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            first_name = st.text_input("First Name*", help="Required field")
            email = st.text_input("Email Address*", help="We'll use this for account recovery")
            
        with col2:
            last_name = st.text_input("Last Name")
            username = st.text_input("Username*", help="This will be visible to others")
        
        password = st.text_input("Password*", type="password", 
                               help="Minimum 8 characters with at least 1 number and 1 special character")
        confirm_password = st.text_input("Confirm Password*", type="password")
        
        agree = st.checkbox("I agree to the Terms of Service and Privacy Policy*", value=False)
        
        if st.form_submit_button("Create Account", type="primary"):
            if not all([first_name, email, username, password, confirm_password, agree]):
                st.error("Please fill all required fields (marked with *)")
            elif not validate_email(email):
                st.error("Please enter a valid email address")
            else:
                is_valid, msg = validate_password(password)
                if not is_valid:
                    st.error(msg)
                elif password != confirm_password:
                    st.error("Passwords don't match!")
                elif len(username) < 4:
                    st.error("Username must be at least 4 characters")
                elif " " in username:
                    st.error("Username cannot contain spaces")
                elif storage.user_exists(email):
                    st.error("This email is already registered!")
                else:
                    try:
                        full_name = f"{first_name} {last_name}" if last_name else first_name
                        user_data = storage.create_user(
                            email=email,
                            password=password,
                            username=username,
                            provider="email",
                            first_name=first_name,
                            last_name=last_name,
                            full_name=full_name
                        )
                        
                        if user_data:
                            st.success("🎉 Account created successfully! Please login with your credentials.")
                            st.session_state.auth_tab = "login"
                            st.rerun()
                        else:
                            st.error("Failed to create account. Please try again.")
                    except Exception as e:
                        logger.error(f"Registration error: {str(e)}")
                        st.error("An error occurred during registration. Please try again.")

# --- CHAT UI ---
def show_chat_ui():
    if st.session_state.get("show_auth"):
        show_auth_ui()
        return

    # Sidebar content (unchanged)
    with st.sidebar:
        st.markdown("""
        <style>
            .logo-container { text-align: center; margin-top: -50px; margin-bottom: 5px; }
            .logo-img { max-width: 280px !important; height: auto; margin: 0 auto; }
            section[data-testid="stSidebar"] > div { padding-top: 0.2rem !important; }
            .prompts-container { margin: 60px 0 !important; }
            .prompt-title {
                font-size: 18px; font-weight: 700; color: #333; margin: 8px 0 10px 0;
                letter-spacing: 0.5px; text-transform: uppercase;
                border-bottom: 1px solid #e0e0e0; padding-bottom: 8px;
            }
            .prompt-btn {
                width: 100%; text-align: left; padding: 10px 15px !important;
                margin: 6px 0 !important; border-radius: 8px !important;
                font-weight: 600 !important; font-size: 13px !important;
                transition: all 0.2s ease !important; border: 1px solid #e0e0e0 !important;
            }
            .prompt-btn:hover {
                background-color: #f5f5f5 !important;
                transform: translateX(3px) !important;
                box-shadow: 2px 2px 8px rgba(0,0,0,0.1) !important;
            }
            .user-message::before {
                content: "👤"; position: absolute; right: -40px; top: 10px;
                font-size: 1.5rem; z-index: 1;
            }
            .bot-message::before {
                content: "💎"; position: absolute; left: -40px; top: 10px;
                font-size: 1.5rem; z-index: 1;
            }
            /* New empty state styles */
            .empty-state-container {
                text-align: center;
                margin: 100px auto;
                max-width: 500px;
                padding: 30px;
                border-radius: 16px;
                background: white;
                box-shadow: 0 4px 12px rgba(0,0,0,0.08);
            }
            .empty-state-title {
                font-size: 24px;
                font-weight: 600;
                color: #555;
                margin-top: 20px;
            }
            .welcome-title {
                font-size: 32px;
                font-weight: 800;
                color: #000;
                margin-bottom: 10px;
            }
        </style>
        <div class="logo-container">
            <img src="https://cdn.shopify.com/s/files/1/0843/6917/8903/files/full_logo_black.png?v=1709732030" 
                 class="logo-img">
        </div>
        <div class="prompts-container">
            <div class="prompt-title">💎 Quick Prompts</div>
        </div>
        """, unsafe_allow_html=True)

        for emoji, text in [
            ("💍", "What is Ringsandi?"),
            ("📍", "Studio Location?"),
            ("✨", "What makes RINGS & I different?"),
            ("💰", "14K vs 18K gold - main differences"),
            ("💎", "Platinum vs gold purity comparison")
        ]:
            if st.button(f"{emoji} {text}", key=f"prompt_{text[:10].lower().replace(' ','_')}",
                         help=f"Ask about {text}", use_container_width=True):
                handle_user_prompt(text)
                
        st.markdown("---")
        
        if st.session_state.logged_in:
            st.markdown(f"""
                <div style="text-align: center; margin: 1rem 0 0.5rem; padding: 8px 0; 
                background: #e8f5e9; border-radius: 8px;">
                    <div style="font-weight: 600; color: #2e7d32;">
                        {st.session_state.full_name or st.session_state.username}
                    </div>
                    <div style="font-size: 12px; color: #4caf50;">You're logged in</div>
                </div>
            """, unsafe_allow_html=True)
            if st.button("Logout", key="sidebar_logout_btn", type="primary", use_container_width=True):
                logout()
        else:
            st.markdown("""
                <div style="text-align: center; margin: 1rem 0 0.5rem; padding: 8px 0; 
                background: #f5f5f5; border-radius: 8px;">
                    <div style="font-weight: 600; color: #333;">Guest User</div>
                    <div style="font-size: 12px; color: #777;">History not saved</div>
                </div>
            """, unsafe_allow_html=True)
            if st.button("Login / Sign Up", key="sidebar_login_btn", type="primary", use_container_width=True):
                st.session_state.show_auth = True
                st.rerun()

    # Main chat UI
    st.markdown("""
    <style>
        .title-container {
            position: fixed; top: 90px; right: 80px; z-index: 1002;
            background: white; padding: 4px 12px; border-radius: 16px;
        }
        .custom-title {
            font-size: 28px !important; font-weight: 800 !important;
            margin: 0 !important; color: #222; letter-spacing: 0.5px;
        }
        .chat-container { max-width: 800px; margin: 0 auto; padding: 20px 0; }
        .user-message, .bot-message {
            position: relative; padding: 12px 16px; margin-bottom: 12px;
            max-width: 80%; box-shadow: 0 1px 2px rgba(0,0,0,0.1);
        }
        .user-message {
            background: #f8f9fa; border-radius: 18px 18px 4px 18px;
            margin-left: auto; border: 1px solid rgba(0,0,0,0.1);
        }
        .bot-message {
            background: white; border-radius: 18px 18px 18px 4px;
            margin-right: auto; border: 1px solid rgba(0,0,0,0.1);
        }
        .file-upload-container {
            position: fixed; 
            bottom: 80px; 
            left: 50%; 
            transform: translateX(-50%); 
            width: 100%; 
            max-width: 800px; 
            padding: 0 20px; 
            z-index: 100;
            display: flex;
            gap: 10px;
        }
        .uploaded-file {
            display: flex; align-items: center; padding: 8px 12px;
            background: #f5f5f5; border-radius: 8px; margin-bottom: 8px;
        }
        .uploaded-file-name { margin-left: 8px; font-size: 14px; }
        .remove-file { margin-left: auto; cursor: pointer; color: #999; }
        
        /* Custom file uploader button */
        .stFileUploader > label { display: none !important; }
        .stFileUploader > button {
            min-width: 40px !important;
            width: 40px !important;
            height: 40px !important;
            padding: 0 !important;
            border-radius: 50% !important;
            background: white !important;
            border: 1px solid #ddd !important;
        }
        .stFileUploader > button:hover {
            background: #f5f5f5 !important;
        }
        .stFileUploader > button > div > p {
            margin: 0 !important;
            font-size: 18px !important;
        }
        
        @media (max-width: 768px) {
            .title-container {
                right: 5px !important; top: 5px !important;
                padding: 4px 12px !important;
            }
            .custom-title { font-size: 20px !important; }
        }
    </style>
    <div class="title-container">
        <div class="custom-title">AI.RingExpert</div>
    </div>
    <div class="chat-container">
    """, unsafe_allow_html=True)

    # Show empty state if no messages, otherwise show messages
    if not st.session_state.get("messages"):
        st.markdown("""
        <div class="empty-state-container">
            <div class="welcome-title">WELCOME TO RINGS & I 💍</div>
            <div class="empty-state-title">What can I help with?</div>
        </div>
        """, unsafe_allow_html=True)
    else:
        for msg in st.session_state.get("messages", []):
            role_class = "user-message" if msg["role"] == "user" else "bot-message"
            st.markdown(f'<div class="{role_class}">{msg["content"]}</div>', unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

    # File upload and chat input
    st.markdown('<div class="file-upload-container">', unsafe_allow_html=True)
    
    # Chat input
    prompt = st.chat_input("Ask...", key="chat_input")
    
    # File uploader with custom styling
    uploaded_file = st.file_uploader(
        "📎",  # This remains to provide the correct icon
        key="file_upload",
        label_visibility="collapsed",
        accept_multiple_files=False,
        help="Upload an image or PDF"
    )
    
    st.markdown('</div>', unsafe_allow_html=True)

    if prompt:
        handle_user_prompt(prompt, uploaded_file)

    # Footer
    st.markdown("""
    <div class="footer-container" style="
        position: fixed; bottom: 18px; left: 0; right: 0;
        background: white; padding: 5px 0; text-align: center;
        z-index: 999; width: calc(100% - 16rem); margin-left: 25rem;
    ">
        <div class="footer-content">
            Powered by RINGS & I | <a href="https://ringsandi.com" target="_blank">Visit ringsandi.com!</a>
        </div>
    </div>
    """, unsafe_allow_html=True)

# --- CSS STYLING ---
def load_css():
    import streamlit as st
    st.markdown("""
    <style>
    :root {
        --primary: #000000;
        --secondary: #FFFFFF;
        --accent: #555555;
        --light: #F9F9F9;
        --dark: #000000;
        --text: #333333;
        --prompt-bg: #F0F0F0;
        --prompt-hover: #E0E0E0;
        --shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
    }
input:focus, textarea:focus {
    outline: none !important;
    box-shadow: none !important;
    border: 1px solid #ccc !important;
}

    [data-testid="stChatInput"] {
        width: 100% !important;
        max-width: 800px !important;
        margin: 0 auto 30px !important;
    }

    [data-testid="stChatInput"] .stTextInput input {
        border-radius: 32px !important;
        padding: 22px 30px !important;
        font-size: 20px !important;
        min-height: 70px !important;
        border: 1px solid #ccc !important;
        box-shadow: var(--shadow) !important;
    }

   [data-testid="stChatInput"] .stTextInput input:focus {
    border-color: #ccc !important;
    box-shadow: none !important;
    outline: none !important;
}


    /* Hide uploader label and text */
    section[data-testid="stFileUploader"] label,
section[data-testid="stFileUploader"] div span {
    display: none !important;
}

section[data-testid="stFileUploader"] button {
    width: 40px !important;
    height: 40px !important;
    border-radius: 50% !important;
    border: 1px solid #ccc !important;
    background-color: #fff !important;
    padding: 0 !important;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    position: relative;
}

    /* Paperclip Icon */
    section[data-testid="stFileUploader"] button::after {
    content: "📎";
    font-size: 20px;
    color: #333;
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
}

section[data-testid="stFileUploader"] button > div {
    display: none !important;
}

    /* Chat bubbles */
    .user-message, .bot-message {
        padding: 12px 16px !important;
        max-width: 80% !important;
        border: 1px solid rgba(0,0,0,0.1) !important;
        box-shadow: 0 1px 2px rgba(0,0,0,0.1) !important;
        margin-bottom: 12px !important;
        animation: fadeIn 0.3s ease-out;
    }

    .user-message {
        background-color: #f8f9fa !important;
        border-radius: 18px 18px 4px 18px !important;
        margin-left: auto !important;
    }

    .bot-message {
        background-color: white !important;
        border-radius: 18px 18px 18px 4px !important;
        margin-right: auto !important;
        position: relative;
    }

    .bot-message::before {
        content: "💎";
        position: absolute;
        left: -40px;
        top: 10px;
        font-size: 1.5rem;
    }

    [data-testid="stSidebar"] {
        background-color: var(--light) !important;
        border-right: 1px solid rgba(0, 0, 0, 0.1);
    }

    .stButton button[kind="secondary"] {
        background-color: var(--prompt-bg);
        color: var(--dark);
        border: 1px solid rgba(0, 0, 0, 0.1);
        border-radius: 10px;
        padding: 6px 10px !important;
        margin: 4px 0;
        font-size: 12px;
        font-weight: 600;
        width: 100%;
        text-align: left;
    }

    .stButton button[kind="secondary"]:hover {
        background-color: var(--prompt-hover);
        transform: translateX(4px);
        box-shadow: 1px 1px 4px rgba(0, 0, 0, 0.08);
    }

    .stButton button[kind="primary"] {
        background-color: var(--primary);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1rem;
    }

    @media (max-width: 768px) {
        .user-message, .bot-message {
            max-width: 90% !important;
        }

        .bot-message::before {
            left: -30px !important;
        }
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    </style>
    """, unsafe_allow_html=True)


# --- OAUTH CALLBACK HANDLER ---
def handle_oauth_callback():
    """Handle OAuth callback after authentication"""
    params = st.query_params.to_dict()
    if params.get("code") and params.get("state") == "google":
        user_info = OAuthService.handle_google_callback(params["code"])
        if user_info:
            email = user_info.get("email")
            if email:
                user = storage.get_user(email)
                if not user:
                    user = storage.create_user(
                        email=email,
                        provider="google",
                        username=email.split('@')[0],
                        full_name=user_info.get("name", ""),
                        first_name=user_info.get("given_name", ""),
                        last_name=user_info.get("family_name", "")
                    )
                if user:
                    complete_login(user)
                    st.query_params.clear()

# --- MAIN APP FLOW ---
def main():
    load_css()
    handle_oauth_callback()
    show_chat_ui()

if __name__ == "__main__":
    main()
