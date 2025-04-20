import streamlit as st
import mysql.connector
import pandas as pd
import google.generativeai as genai
import re
import bcrypt

# --- Configuration ---
genai.configure(api_key="AIzaSyDf5OVlcDYq6ZTO5bSlX_juje8EvE1rvVI")
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "root",
    "database": "insight_database"
}
model = genai.GenerativeModel('gemini-1.5-pro', generation_config={"temperature": 0.3})

# --- Helper Functions ---
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(stored_hash: str, password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

def enforce_distinct(sql: str) -> str:
    pattern = re.compile(r"select\s+", re.IGNORECASE)
    if pattern.search(sql) and "distinct" not in sql.lower():
        return pattern.sub("SELECT DISTINCT ", sql, count=1)
    return sql

def generate_sql(question: str) -> str:
    schema = """
    Tables:
    - mentors (name, utd_email, skill, availability_day, availability_time, status)
    - professors (id, first_name, last_name, email)
    - courses (course_id, title, class_level)
    - grades (professor_id, course_id, section_id, A, Aminus, Bplus, B, Bminus, Cplus, C, Cminus, Dplus, D, Dminus, F, W)
    """
    prompt = f"You are a SQL query generator. You generate concise queries with DISTINCT keyword for the provided prompt, with out any code blocks or markdown formatting. \
                 if prompt isn't related to getting SQL query. \
                 Course ID is of format <title><class_level> eg: CS1234. \
                 schema: {schema}"
    
    try:
        response = model.generate_content(prompt + "\nQ: " + question)
        sql_match = re.search(r"SELECT\s.+?FROM\s.+?(WHERE\s.+?)?;", response.text, re.IGNORECASE | re.DOTALL)
        if sql_match:
            clean_sql = enforce_distinct(sql_match.group(0).replace("`", "").strip())
            if any(cmd in clean_sql.upper() for cmd in ["INSERT", "UPDATE", "DELETE", "DROP"]):
                return "INVALID"
            return clean_sql
        return "INVALID"
    except Exception as e:
        st.error(f"Gemini Error: {str(e)}")
        return "INVALID"

def run_query(sql: str) -> pd.DataFrame:
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute(sql)
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
        df = pd.DataFrame(rows, columns=columns)
        cursor.close()
        conn.close()
        return df
    except Exception as e:
        st.error(f"Query failed: {str(e)}")
        return pd.DataFrame()

# --- Streamlit UI ---
st.set_page_config(page_title="UTD Academic System", layout="wide")
tab1, tab2, tab3 = st.tabs(["📚 Academic Query", "🤝 Mentor Booking", "🔐 Mentor Portal"])

with tab1:
    st.title("Academic Database Query Assistant")
    question = st.text_input("Ask about courses, professors, or grades:")
    
    if st.button("Generate Query"):
        with st.status("Processing..."):
            sql = generate_sql(question)
            if sql == "INVALID":
                st.error("Invalid query generated")
                st.stop()
            
            st.subheader("Generated SQL")
            st.code(sql, language="sql")
            
            df = run_query(sql)
            if not df.empty:
                st.subheader("Results")
                st.dataframe(df)
                summary = model.generate_content(f"Summarize: {question}\nData: {df.head(3).to_string()}").text
                st.success(summary)
            else:
                st.warning("No results found")

with tab2:
    st.title("Mentor Booking System")
    status_icons = {"available": "🟢", "busy": "🔴", "afk": "🟡", "done": "⚫"}
    
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)
    
    # Available Mentors
    st.subheader("Available Mentors")
    cursor.execute("SELECT * FROM mentors WHERE status = 'available'")
    mentors = cursor.fetchall()
    
    # Get availability options with null handling
    available_days = sorted(set(m['availability_day'].strip() for m in mentors if m['availability_day']))
    available_times = sorted(set(m['availability_time'].strip() for m in mentors if m['availability_time']))
    
    for mentor in mentors:
        st.markdown(f"""
        {status_icons[mentor['status'].lower()]} {mentor['name']}  
        🛠 {mentor['skill']}  
        📅 {mentor['availability_day']} {mentor['availability_time']}  
        📧 {mentor['utd_email']}
        """)
    
    # Booking System
    with st.form("Booking Form"):
        mentee_name = st.text_input("Your Name")
        mentor_list = [m['name'] for m in mentors]
        selected_mentor = st.selectbox("Choose Mentor", mentor_list)
        
        col1, col2 = st.columns(2)
        with col1:
            requested_day = st.selectbox("Preferred Day", available_days)
        with col2:
            requested_time = st.text_input("Preferred Time (e.g., 4-6pm)")
        
        if st.form_submit_button("Book Session"):
            cursor.execute("""
            SELECT id, availability_day, availability_time 
            FROM mentors WHERE name = %s
            """, (selected_mentor,))
            mentor = cursor.fetchone()
            
            valid_day = requested_day.strip().lower() == mentor['availability_day'].strip().lower()
            valid_time = requested_time.strip().lower() == mentor['availability_time'].strip().lower()
            
            if valid_day and valid_time:
                slot = f"{requested_day} {requested_time}"
                cursor.execute("""
                SELECT * FROM mentor_bookings 
                WHERE mentor_id = %s AND slot = %s AND status = 'pending'
                """, (mentor['id'], slot))
                
                if not cursor.fetchone():
                    cursor.execute("""
                    INSERT INTO mentor_bookings (mentor_id, mentee_name, slot)
                    VALUES (%s, %s, %s)
                    """, (mentor['id'], mentee_name, slot))
                    cursor.execute("UPDATE mentors SET status = 'busy' WHERE id = %s", (mentor['id'],))
                    conn.commit()
                    st.success("✅ Booking confirmed!")
                else:
                    st.error("⛔ Slot already booked!")
            else:
                st.error("⛔ Invalid day/time combination")
    
    cursor.close()
    conn.close()

with tab3:
    st.title("Mentor Portal")
    
    # Authentication Section
    with st.expander("🔑 Mentor Login", expanded=True):
        mentor_email = st.text_input("UTD Email")
        mentor_password = st.text_input("Password", type="password")
        
        if st.button("Login"):
            conn = mysql.connector.connect(**DB_CONFIG)
            cursor = conn.cursor(dictionary=True)
            
            try:
                cursor.execute("SELECT * FROM mentors WHERE utd_email = %s", (mentor_email,))
                mentor = cursor.fetchone()
                
                if mentor and verify_password(mentor['password_hash'], mentor_password):
                    st.session_state.authenticated_mentor = mentor
                    st.success("Authentication successful!")
                else:
                    st.error("Invalid credentials")
                    
            except Exception as e:
                st.error(f"Authentication error: {str(e)}")
            finally:
                cursor.close()
                conn.close()
    
    # Status Update Section
    if 'authenticated_mentor' in st.session_state:
        mentor = st.session_state.authenticated_mentor
        st.subheader(f"Welcome, {mentor['name']}!")
        
        with st.form("update_availability"):
            new_day = st.selectbox(
                "Available Day",
                ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
                index=["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"].index(mentor['availability_day'])
            )
            new_time = st.text_input("Available Time", value=mentor['availability_time'])
            new_status = st.selectbox(
                "Status", 
                list(status_icons.keys()),
                index=list(status_icons.keys()).index(mentor['status'])
            )
            
            if st.form_submit_button("Update Availability"):
                conn = mysql.connector.connect(**DB_CONFIG)
                cursor = conn.cursor()
                try:
                    cursor.execute("""
                        UPDATE mentors 
                        SET availability_day = %s,
                            availability_time = %s,
                            status = %s
                        WHERE id = %s
                    """, (new_day, new_time, new_status, mentor['id']))
                    conn.commit()
                    st.success("Availability updated successfully!")
                    st.session_state.authenticated_mentor = None  # Force re-authentication
                except Exception as e:
                    st.error(f"Update failed: {str(e)}")
                finally:
                    cursor.close()
                    conn.close()
        
        if st.button("Logout"):
            st.session_state.authenticated_mentor = None
            st.rerun()
    
    # Registration Section
    with st.expander("📝 New Mentor Registration"):
        with st.form("mentor_registration"):
            name = st.text_input("Name*")
            utd_email = st.text_input("UTD Email* (e.g., abc123@utdallas.edu)")
            skill = st.text_input("Skill (comma-separated)*")
            availability_day = st.selectbox("Available Day*", ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"])
            availability_time = st.text_input("Available Time* (e.g., 2-4 PM)")
            password = st.text_input("Password*", type="password")
            confirm_password = st.text_input("Confirm Password*", type="password")
            
            if st.form_submit_button("Register"):
                errors = []
                if not all([name, utd_email, skill, availability_day, availability_time, password]):
                    errors.append("All fields marked with * are required")
                if "@utdallas.edu" not in utd_email:
                    errors.append("Must use UTD email address")
                if password != confirm_password:
                    errors.append("Passwords do not match")
                if len(password) < 8:
                    errors.append("Password must be at least 8 characters")
                
                if errors:
                    for error in errors:
                        st.error(error)
                else:
                    conn = mysql.connector.connect(**DB_CONFIG)
                    cursor = conn.cursor()
                    try:
                        hashed_pw = hash_password(password)
                        cursor.execute("""
                            INSERT INTO mentors 
                            (name, utd_email, skill, availability_day, availability_time, password_hash, status)
                            VALUES (%s, %s, %s, %s, %s, %s, 'available')
                        """, (
                            name.strip(),
                            utd_email.strip().lower(),
                            skill.strip(),
                            availability_day.strip(),
                            availability_time.strip(),
                            hashed_pw
                        ))
                        conn.commit()
                        st.success("Registration successful! You can now log in.")
                    except mysql.connector.IntegrityError:
                        st.error("This email is already registered")
                    except Exception as e:
                        st.error(f"Registration failed: {str(e)}")
                    finally:
                        cursor.close()
                        conn.close()

st.divider()
st.write("Sample Queries:")
st.markdown("""
- "Show computer science professors"
- "List available Python mentors"
- "Find courses with 'Data' in title"
""")