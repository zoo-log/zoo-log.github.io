import type { SiteConfig } from './types';
import { DEFAULT_LOCALE, SUPPORTED_LOCALES } from './locales';

const siteConfig: SiteConfig = {
  // Basic site information
  siteUrl: 'https://morethan-log-astro.sereja.com',
  title: {
    kr: 'Zoo-Log',
    en: 'Zoo-Log',
  },
  description: {
    kr: 'I love Programming, Hacking, Quantitative Trading',
    en: 'I love Programming, Hacking, Quantitative Trading',
  },

  // Author information
  author: {
    name: {
      kr: 'ZooLog',
      en: 'ZooLog',
    },
    email: 'qkrwngus3563@naver.com',
    avatar: '/img/avatar.png',
    bio: {
      kr: 'I love Programming, Hacking, Quantitative Trading',
      en: 'I love Programming, Hacking, Quantitative Trading', 
    },
  },

  // Blog settings
  postsPerPage: 10,
  featuredImageFallback: '/img/posts/placeholder.svg',

  // Contact & social links
  contactLinks: [
    {
      id: 'github',
      label: {
        kr: 'GitHub',
        en: 'GitHub',
      },
      url: {
        kr: 'https://github.com/zoo-log',
        en: 'https://github.com/zoo-log',
      },
      iconSvg: `<svg
  stroke="currentColor"
  fill="currentColor"
  stroke-width="0"
  viewBox="0 0 1024 1024"
  class="icon"
  height="1em"
  width="1em"
  xmlns="http://www.w3.org/2000/svg"
>
  <path d="M511.6 76.3C264.3 76.2 64 276.4 64 523.5 64 718.9 189.3 885 363.8 946c23.5 5.9 19.9-10.8 19.9-22.2v-77.5c-135.7 15.9-141.2-73.9-150.3-88.9C215 726 171.5 718 184.5 703c30.9-15.9 62.4 4 98.9 57.9 26.4 39.1 77.9 32.5 104 26 5.7-23.5 17.9-44.5 34.7-60.8-140.6-25.2-199.2-111-199.2-213 0-49.5 16.3-95 48.3-131.7-20.4-60.5 1.9-112.3 4.9-120 58.1-5.2 118.5 41.6 123.2 45.3 33-8.9 70.7-13.6 112.9-13.6 42.4 0 80.2 4.9 113.5 13.9 11.3-8.6 67.3-48.8 121.3-43.9 2.9 7.7 24.7 58.3 5.5 118 32.4 36.8 48.9 82.7 48.9 132.3 0 102.2-59 188.1-200 212.9a127.5 127.5 0 0 1 38.1 91v112.5c.8 9 0 17.9 15 17.9 177.1-59.7 304.6-227 304.6-424.1 0-247.2-200.4-447.3-447.5-447.3z"></path>
</svg>`,
    },
    {
      id: 'instagram',
      label: {
        kr: 'Instagram',
        en: 'Instagram',
      },
      url: {
        kr: 'https://www.instagram.com/zooo._.hyeon/',
        en: 'https://www.instagram.com/zooo._.hyeon/',
      },
      icon: '📸',
    },
    /*{
      id: 'youtube',
      label: {
        en: 'YouTube',
        ru: 'YouTube',
      },
      url: {
        en: 'https://www.youtube.com/@yourusername',
        ru: 'https://www.youtube.com/@yourusername-ru',
      },
      icon: '▶️',
    },
    {
      id: 'twitch',
      label: {
        en: 'Twitch',
        ru: 'Twitch',
      },
      url: {
        en: 'https://www.twitch.tv/yourusername',
        ru: 'https://www.twitch.tv/yourusername-ru',
      },
      icon: '🎮',
    },
    */
  ],

  projects: [
    /*
    {
      id: 'morethan-log-astro',
      url: 'https://github.com/JustSereja/morethan-log-astro',
      label: {
        en: 'Morethan-Log for Astro',
        ru: 'Morethan-Log для Astro',
      },
      iconSvg: `<svg
  stroke="currentColor"
  fill="currentColor"
  stroke-width="0"
  viewBox="0 0 1024 1024"
  class="icon"
  height="1em"
  width="1em"
  xmlns="http://www.w3.org/2000/svg"
>
  <path d="M511.6 76.3C264.3 76.2 64 276.4 64 523.5 64 718.9 189.3 885 363.8 946c23.5 5.9 19.9-10.8 19.9-22.2v-77.5c-135.7 15.9-141.2-73.9-150.3-88.9C215 726 171.5 718 184.5 703c30.9-15.9 62.4 4 98.9 57.9 26.4 39.1 77.9 32.5 104 26 5.7-23.5 17.9-44.5 34.7-60.8-140.6-25.2-199.2-111-199.2-213 0-49.5 16.3-95 48.3-131.7-20.4-60.5 1.9-112.3 4.9-120 58.1-5.2 118.5 41.6 123.2 45.3 33-8.9 70.7-13.6 112.9-13.6 42.4 0 80.2 4.9 113.5 13.9 11.3-8.6 67.3-48.8 121.3-43.9 2.9 7.7 24.7 58.3 5.5 118 32.4 36.8 48.9 82.7 48.9 132.3 0 102.2-59 188.1-200 212.9a127.5 127.5 0 0 1 38.1 91v112.5c.8 9 0 17.9 15 17.9 177.1-59.7 304.6-227 304.6-424.1 0-247.2-200.4-447.3-447.5-447.3z"></path>
</svg>`,
    },
    */
  ],

  categories: {
    blog: {
      enabled: true,
      path: '/blog',
      icon: '💻',
      label: {
        kr: 'Blog',
        en: 'Blog',
      },
      description: {
        kr: '공부 일지',
        en: 'Personal thoughts, experiences, and insights from my journey',
      },
    },
    technology: {
      enabled: true,
      path: '/technology',
      icon: '🚀',
      label: {
        kr: 'Technology',
        en: 'Technology',
      },
      description: {
        kr: '기술 일지',
        en: 'Deep dives into web development, tools, and best practices',
      },
    },
    projects: {
      enabled: true,
      path: '/projects',
      icon: '🛠️',
      label: {
        kr: 'Projects',
        en: 'Projects',
      },
      description: {
        kr: '프로젝트 일지',
        en: 'My Project Diary',
      },
    },
  },

  navigation: [
    {
      id: 'about',
      labelKey: 'ui.about',
      translationKey: 'about',
    },
  ],

  // Feature toggles
  features: {
    darkMode: true,
    search: true,
    rss: true,
    sitemap: true,
    imageLightbox: true,
    postNavigation: true,
    readingTime: true,
    viewCounter: false,
  },

  // SEO & Meta tags
  seo: {
    defaultImage: '/img/og-image.svg',
    twitterHandle: 'astrodotbuild',
    googleAnalytics: '',
  },

  // Language settings
  defaultLanguage: DEFAULT_LOCALE,
  languages: [...SUPPORTED_LOCALES],

  // Date format settings
  dateFormats: {
    kr: {
      locale: 'ko-KR',
      options: {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      },
      compactOptions: {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      },
    },
    en: {
      locale: 'en-US',
      options: {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      },
      compactOptions: {
        year: '2-digit',
        month: 'short',
        day: 'numeric',
      },
    },
  },
};

export default siteConfig;
export type { SiteConfig } from './types';
export { SUPPORTED_LOCALES, SUPPORTED_LOCALES as SUPPORTED_LANGUAGES } from './locales';
