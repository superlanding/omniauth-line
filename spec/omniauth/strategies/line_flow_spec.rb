require 'spec_helper'

describe 'LINE 登入 request phase 到 callback' do
  let(:inner_app) do
    lambda do |env|
      body = env['omniauth.auth'] ? env['omniauth.auth'].uid : 'no auth'
      [200, {}, [body]]
    end
  end
  let(:app) { OmniAuth::Strategies::Line.new(inner_app, 'CHANNEL_ID', 'CHANNEL_SECRET') }
  let(:session) { {} }

  before do
    OmniAuth.config.allowed_request_methods = %i[get post]
    OmniAuth.config.silence_get_warning = true
    OmniAuth.config.request_validation_phase = nil
    OmniAuth.config.on_failure = lambda do |env|
      [302, { 'location' => '/failure' }, [env['omniauth.error.type'].to_s]]
    end

    stub_request(:post, 'https://api.line.me/oauth2/v2.1/token')
      .to_return(
        status: 200,
        headers: { 'Content-Type' => 'application/json' },
        body: { access_token: 'ACCESS', token_type: 'Bearer', expires_in: 2_592_000, id_token: 'ID_TOKEN' }.to_json
      )
    stub_request(:get, 'https://api.line.me/v2/profile')
      .to_return(
        status: 200,
        headers: { 'Content-Type' => 'application/json' },
        body: { userId: 'U123', displayName: 'Foo', pictureUrl: 'https://example.com/a.jpg' }.to_json
      )
    stub_request(:post, 'https://api.line.me/oauth2/v2.1/verify')
      .to_return(status: 200, body: { email: 'foo@example.com' }.to_json)
  end

  after do
    OmniAuth.config.on_failure = OmniAuth::FailureEndpoint
  end

  def start_sign_in
    response = Rack::MockRequest.new(app).get('/auth/line', 'rack.session' => session)
    expect(response.status).to eq(302)
    Rack::Utils.parse_query(URI(response.location).query)
  end

  def callback(state)
    Rack::MockRequest.new(app).get("/auth/line/callback?code=CODE&state=#{state}", 'rack.session' => session)
  end

  it '授權頁帶的 redirect_uri 是不含 query 的 callback 網址' do
    params = start_sign_in

    expect(params['redirect_uri']).to eq('http://example.org/auth/line/callback')
    expect(params['state']).to match(/\A\h{48}\z/)
  end

  it 'callback 的 state 相符時，拿 token 並取得 LINE 的 uid' do
    state = start_sign_in['state']

    response = callback(state)

    expect(response.body).to eq('U123')
    expect(
      a_request(:post, 'https://api.line.me/oauth2/v2.1/token')
        .with(body: hash_including('code' => 'CODE', 'redirect_uri' => 'http://example.org/auth/line/callback'))
    ).to have_been_made.once
  end

  it '同一個 session 開了兩次授權頁，用先開的那個完成也能登入' do
    first_state = start_sign_in['state']
    start_sign_in

    response = callback(first_state)

    expect(response.body).to eq('U123')
  end

  it '完成一次登入後，下一次授權頁仍導到 access.line.me' do
    callback(start_sign_in['state'])

    response = Rack::MockRequest.new(app).get('/auth/line', 'rack.session' => session)

    expect(URI(response.location).host).to eq('access.line.me')
  end

  it 'callback 的 state 不在 session 裡時，回 csrf_detected' do
    start_sign_in

    response = callback('0' * 48)

    expect(response.location).to eq('/failure')
    expect(response.body).to eq('csrf_detected')
  end

  it '同一個 state 的 callback 打第二次時，回 csrf_detected' do
    state = start_sign_in['state']
    callback(state)

    response = callback(state)

    expect(response.body).to eq('csrf_detected')
  end
end
