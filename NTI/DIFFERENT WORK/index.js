document.addEventListener('DOMContentLoaded', () => {
  const card = document.querySelector('.hero-card');

  if (card) {
    requestAnimationFrame(() => {
      card.classList.add('is-visible');
    });
  }

  const heroShell = document.querySelector('.hero-shell');
  heroShell?.addEventListener('pointermove', (event) => {
    const rect = heroShell.getBoundingClientRect();
    const x = (event.clientX - rect.left) / rect.width - 0.5;
    const y = (event.clientY - rect.top) / rect.height - 0.5;

    if (card) {
      card.style.transform = `perspective(1000px) rotateY(${x * 4}deg) rotateX(${y * -4}deg) translateY(0)`;
    }
  });

  heroShell?.addEventListener('pointerleave', () => {
    if (card) {
      card.style.transform = '';
    }
  });
});


// comments codes 
//card to perform save task 
