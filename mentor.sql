-- -- CREATE TABLE mentors (
-- --     id INT AUTO_INCREMENT PRIMARY KEY,
-- --     name VARCHAR(100),
-- --     skill VARCHAR(100),
-- --     availability VARCHAR(100),
-- --     email VARCHAR(100)
-- -- );

-- -- INSERT INTO mentors (name, skill, availability, email) VALUES
-- -- ('Alice Smith', 'Python Programming', 'Mon 3-4pm', 'alice@utd.edu'),
-- -- ('Bob Lee', 'Data Analysis', 'Tue 5-6pm', 'bob@utd.edu'),
-- -- ('Cindy Zhao', 'Resume Writing', 'Wed 2-3pm', 'cindy@utd.edu'),
-- -- ('Daniel Kim', 'Java', 'Fri 4-5pm', 'daniel@utd.edu'),
-- -- ('Emma Patel', 'Machine Learning', 'Thu 1-2pm', 'emma@utd.edu');

-- -- ALTER TABLE mentors ADD COLUMN status ENUM('available', 'busy', 'afk', 'done') DEFAULT 'available';

-- -- CREATE TABLE IF NOT EXISTS mentor_bookings (
-- --     id INT AUTO_INCREMENT PRIMARY KEY,
-- --     mentor_id INT,
-- --     mentee_name VARCHAR(100),
-- --     slot VARCHAR(100),
-- --     status ENUM('pending', 'confirmed', 'done') DEFAULT 'pending',
-- --     timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
-- --     FOREIGN KEY (mentor_id) REFERENCES mentors(id)
-- -- );

-- -- 1. Rename existing columns to match CSV headers
-- -- ALTER TABLE mentors 
-- -- RENAME COLUMN email TO utd_email;

-- -- -- 2. Add new columns from CSV
-- -- ALTER TABLE mentors
-- -- ADD COLUMN availability_day VARCHAR(50) AFTER skill,
-- -- ADD COLUMN availability_time VARCHAR(50) AFTER availability_day;

-- -- -- 3. Modify column types to match CSV data
-- -- ALTER TABLE mentors
-- -- MODIFY COLUMN skill TEXT,
-- -- MODIFY COLUMN utd_email VARCHAR(255) UNIQUE;

-- ALter table mentors
-- drop column availability;

-- INSERT INTO mentors (name, skill, availability_day, availability_time, utd_email, status, password) VALUES
-- ('Himanshu Goswami', 'Java, Python, SQL', 'Friday', '4:00 PM - 6:00 PM', 'hxg230030@utdallas.edu', 'Available','Himanshu123'),
-- ('Anaya Patel', 'Cybersecurity, Communication', 'Tuesday', '10:00 AM - 12:00 PM', 'anaya.patel@utdallas.edu', 'Available','Anaya123'),
-- ('Meera Mehta', 'Web Development, Communication', 'Wednesday', '2:00 PM - 4:00 PM', 'meera.mehta@utdallas.edu', 'Available','Meera123'),
-- ('Aarav Sharma', 'Operating Systems, Communication', 'Tuesday', '5:00 PM - 7:00 PM', 'aarav.sharma@utdallas.edu', 'Available','Aarav'),
-- ('Rohan Das', 'SQL, Communication', 'Tuesday', '10:00 AM - 12:00 PM', 'rohan.das@utdallas.edu', 'Busy','Rohan123'),
-- ('Rohan Kumar', 'Data Science, Communication', 'Friday', '2:00 PM - 4:00 PM', 'rohan.kumar@utdallas.edu', 'Available',),
-- ('Ishaan Patel', 'Java, Communication', 'Monday', '2:00 PM - 4:00 PM', 'ishaan.patel@utdallas.edu', 'Available'),
-- ('Ishaan Mehta', 'Cybersecurity, Communication', 'Thursday', '2:00 PM - 4:00 PM', 'ishaan.mehta@utdallas.edu', 'Busy'),
-- ('Meera Kumar', 'Cybersecurity, Communication', 'Wednesday', '2:00 PM - 4:00 PM', 'meera.kumar@utdallas.edu', 'Busy'),
-- ('Anaya Das', 'SQL, Communication', 'Friday', '10:00 AM - 12:00 PM', 'anaya.das@utdallas.edu', 'Available'),
-- ('Tara Mehta', 'Python, Communication', 'Friday', '5:00 PM - 7:00 PM', 'tara.mehta@utdallas.edu', 'Available');

-- ALTER TABLE mentors 
-- ADD COLUMN password_hash VARCHAR(255) NOT NULL AFTER utd_email;

-- UPDATE mentors
-- set availability_time='4:00 PM - 6:00 PM' where name='Himanshu Goswami'; 

CREATE TABLE events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_date DATE,
    building VARCHAR(255),
    room VARCHAR(100),
    event_name VARCHAR(255),
    organization_name VARCHAR(255),
    contact_name VARCHAR(255),
    setup_minutes INT,
    start_time DATETIME,
    end_time DATETIME,
    teardown_minutes INT,
    status_description VARCHAR(50),
    status_color VARCHAR(20)
);