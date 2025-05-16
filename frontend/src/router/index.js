import { createRouter, createWebHistory } from 'vue-router'
import Home from '../views/Home.vue'
import About from '../views/About.vue'
import Contacts from '../views/Contacts.vue'
import Teachers from '../views/Teachers.vue'
import Courses from '../views/Courses.vue'
import Login from '../views/Login.vue'
import Register from '../views/Register.vue'

const routes = [
  { 
    path: '/', 
    name: 'Home', 
    component: Home 
  },
  { 
    path: '/about', 
    name: 'About', 
    component: About 
  },
  { 
    path: '/contacts', 
    name: 'Contacts', 
    component: Contacts 
  },
  { 
    path: '/teachers', 
    name: 'Teachers', 
    component: Teachers 
  },
  { 
    path: '/courses', 
    name: 'Courses', 
    component: Courses 
  },
  { 
    path: '/login', 
    name: 'Login', 
    component: Login 
  },
  { 
    path: '/register', 
    name: 'Register', 
    component: Register 
  },
  // Новые маршруты для преподавателей
  {
    path: '/teachers/add',
    name: 'AddTeacher',
    component: () => import('../views/TeacherForm.vue'),
    props: { mode: 'add' }
  },
  {
    path: '/teachers/edit/:id',
    name: 'EditTeacher',
    component: () => import('../views/TeacherForm.vue'),
    props: { mode: 'edit' }
  },
  {
    path: '/teachers/view/:id',
    name: 'ViewTeacher',
    component: () => import('../views/TeacherView.vue')
  },
  // Новые маршруты для курсов
  {
    path: '/courses/add',
    name: 'AddCourse',
    component: () => import('../views/CourseForm.vue'),
    props: { mode: 'add' }
  },
  {
    path: '/courses/edit/:id',
    name: 'EditCourse',
    component: () => import('../views/CourseForm.vue'),
    props: { mode: 'edit' }
  },
  {
    path: '/courses/view/:id',
    name: 'ViewCourse',
    component: () => import('../views/CourseView.vue')
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

export default router