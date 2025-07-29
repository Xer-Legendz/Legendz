# RESTORATION
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>My Portfolio</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; font-family: Arial, sans-serif; }
    body { background: #f8f9fa; color: #333; line-height: 1.6; }
    header { position: fixed; width: 100%; top: 0; left: 0; background: #111; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; z-index: 1000; }
    header h1 { color: #fff; }
    nav a { color: #fff; margin-left: 1.5rem; text-decoration: none; transition: color 0.3s; }
    nav a:hover { color: #00bcd4; }

    section { padding: 100px 20px; max-width: 1100px; margin: auto; }
    #hero { height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; background: #222; color: #fff; }
    #hero h2 { font-size: 3rem; }
    #hero p { font-size: 1.2rem; margin-top: 10px; }
    #hero button { margin-top: 20px; padding: 10px 20px; background: #00bcd4; border: none; color: white; cursor: pointer; font-size: 1rem; border-radius: 5px; transition: 0.3s; }
    #hero button:hover { background: #0097a7; }

    #about, #projects, #contact { background: #fff; margin-top: 50px; border-radius: 10px; padding: 50px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    h2 { margin-bottom: 20px; text-align: center; }

    /* Projects Grid */
    .projects-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
    .project { background: #f1f1f1; border-radius: 8px; overflow: hidden; transition: transform 0.3s; }
    .project:hover { transform: scale(1.05); }
    .project img { width: 100%; height: 180px; object-fit: cover; }
    .project h3 { padding: 15px; }

    /* Contact Form */
    form { display: flex; flex-direction: column; gap: 15px; }
    input, textarea { padding: 10px; border: 1px solid #ccc; border-radius: 5px; font-size: 1rem; }
    button { padding: 10px; background: #00bcd4; border: none; color: white; cursor: pointer; border-radius: 5px; transition: background 0.3s; }
    button:hover { background: #0097a7; }

    footer { text-align: center; padding: 20px; background: #111; color: #fff; margin-top: 50px; }
    html { scroll-behavior: smooth; }
  </style>
</head>
<body>

<header>
  <h1>My Portfolio</h1>
  <nav>
    <a href="#hero">Home</a>
    <a href="#about">About</a>
    <a href="#projects">Projects</a>
    <a href="#contact">Contact</a>
  </nav>
</header>

<section id="hero">
  <h2>Hello, I'm Restoration</h2>
  <p>Frontend Developer | Designer | Problem Solver</p>
  <button onclick="document.getElementById('projects').scrollIntoView({behavior:'smooth'});">See My Work</button>
</section>

<section id="about">
  <h2>About Me</h2>
  <p>Hi! I'm a passionate web developer with experience in building beautiful and responsive websites. I enjoy turning ideas into reality using modern web technologies.</p>
</section>

<section id="projects">
  <h2>My Projects</h2>
  <div class="projects-container">
    <div class="project">
      <img src="https://via.placeholder.com/300x180" alt="Project 1">
      <h3>Project One</h3>
    </div>
    <div class="project">
      <img src="https://via.placeholder.com/300x180" alt="Project 2">
      <h3>Project Two</h3>
    </div>
    <div class="project">
      <img src="https://via.placeholder.com/300x180" alt="Project 3">
      <h3>Project Three</h3>
    </div>
  </div>
</section>

<section id="contact">
  <h2>Contact Me</h2>
  <form id="contactForm">
    <input type="text" placeholder="Your Name" required>
    <input type="email" placeholder="Your Email" required>
    <textarea rows="5" placeholder="Your Message" required></textarea>
    <button type="submit">Send</button>
  </form>
</section>

<footer>
  &copy; 2025 My Portfolio. All rights reserved.
</footer>

<script>
  // Simple contact form handler
  document.getElementById('contactForm').addEventListener('submit', function(e) {
    e.preventDefault();
    alert('Thank you for reaching out! I will get back to you soon.');
    this.reset();
  });
</script>

</body>
</html>
