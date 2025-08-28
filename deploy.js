#!/usr/bin/env node

const { execSync } = require('child_process');

console.log('🚀 Deploying to Cloudflare Workers...\n');

try {
  // Check if we're in a git repository
  execSync('git status', { stdio: 'inherit' });
  
  // Check if there are changes to commit
  const status = execSync('git status --porcelain', { encoding: 'utf8' });
  
  if (status.trim()) {
    console.log('📝 Committing changes...');
    execSync('git add .', { stdio: 'inherit' });
    execSync('git commit -m "Update worker and data files"', { stdio: 'inherit' });
    
    console.log('📤 Pushing to GitHub...');
    execSync('git push origin main', { stdio: 'inherit' });
  } else {
    console.log('✅ No changes to commit');
  }
  
  console.log('\n🌐 Deploying to Cloudflare Workers...');
  execSync('wrangler deploy', { stdio: 'inherit' });
  
  console.log('\n🎉 Deployment successful!');
  console.log('\n📋 Next steps:');
  console.log('1. Wait 1 minute for cache to expire');
  console.log('2. Test your worker with an email from your updated list');
  console.log('3. Check Cloudflare Worker logs for any errors');
  
} catch (error) {
  console.error('❌ Deployment failed:', error.message);
  console.log('\n💡 Troubleshooting:');
  console.log('1. Make sure you have wrangler installed: npm install -g wrangler');
  console.log('2. Make sure you\'re logged in: wrangler login');
  console.log('3. Check your wrangler.toml configuration');
} 