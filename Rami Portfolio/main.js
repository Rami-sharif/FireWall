document.addEventListener('DOMContentLoaded', () => {
    const projectsBtn = document.getElementById('projectsBtn');
    const backBtn = document.getElementById('backBtn');
    const projectsSection = document.getElementById('projectsSection');
    const mainContent = document.querySelector('.content');
    const menuToggle = document.getElementById('menuToggle');
    const sidebar = document.querySelector('.sidebar');

    // إضافة التمرير السلس للمحتوى
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            document.querySelector(this.getAttribute('href')).scrollIntoView({
                behavior: 'smooth'
            });
        });
    });

    projectsBtn.addEventListener('click', () => {
        projectsSection.classList.remove('hidden');
        projectsSection.style.transform = 'translateX(0)';
        mainContent.style.transform = 'translateX(-100%)';
        mainContent.style.opacity = '0';
        
        projectsBtn.style.display = 'none';
        backBtn.style.display = 'inline-block';

        // إغلاق القائمة الجانبية في الشاشات الصغيرة
        if (window.innerWidth <= 768) {
            sidebar.classList.remove('active');
            menuToggle.classList.remove('active');
        }
    });

    backBtn.addEventListener('click', () => {
        projectsSection.style.transform = 'translateX(100%)';
        mainContent.style.transform = 'translateX(0)';
        mainContent.style.opacity = '1';
        
        setTimeout(() => {
            projectsSection.classList.add('hidden');
        }, 500);
        
        projectsBtn.style.display = 'inline-block';
        backBtn.style.display = 'none';

        // إغلاق القائمة الجانبية في الشاشات الصغيرة
        if (window.innerWidth <= 768) {
            sidebar.classList.remove('active');
            menuToggle.classList.remove('active');
        }
    });

    // تفعيل/إخفاء القائمة الجانبية وتغيير شكل الزر
    menuToggle.addEventListener('click', () => {
        menuToggle.classList.toggle('active');
        sidebar.classList.toggle('active');
    });

    // إغلاق القائمة عند النقر خارجها
    document.addEventListener('click', (e) => {
        if (!sidebar.contains(e.target) && !menuToggle.contains(e.target)) {
            sidebar.classList.remove('active');
            menuToggle.classList.remove('active');
        }
    });

    // إغلاق القائمة عند النقر على أي رابط
    document.querySelectorAll('.sidebar a').forEach(link => {
        link.addEventListener('click', () => {
            if (window.innerWidth <= 768) {
                sidebar.classList.remove('active');
                menuToggle.classList.remove('active');
            }
        });
    });

    // تحديث حالة القائمة عند تغيير حجم النافذة
    window.addEventListener('resize', () => {
        if (window.innerWidth > 768) {
            sidebar.classList.remove('active');
            menuToggle.classList.remove('active');
        }
    });
});
