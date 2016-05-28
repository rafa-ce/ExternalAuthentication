using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Microsoft.Owin.Testing;
using ExternalAuthentication.WebAPI;
using System.Net.Http;
using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
using System.Net;

namespace ExternalAuthentication.Tests.WebAPI
{
    [TestClass]
    public class ApiAuthorizationServerProviderTest
    {
        [TestMethod]
        public async Task GetTokenWithUserValid()
        {
            using (var server = TestServer.Create<Startup>())
            {
                var response = await server.CreateRequest("/token").And(x => x.Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("username", "user"),
                    new KeyValuePair<string, string>("password", "123"),
                    new KeyValuePair<string, string>("grant_type", "password")
                })).PostAsync();

                response.IsSuccessStatusCode.Should().BeTrue();
                response.StatusCode.Should().Be(HttpStatusCode.OK);
                (await response.Content.ReadAsStringAsync()).Should().NotBeNullOrWhiteSpace();
            }
        }

        [TestMethod]
        public async Task GetTokenWithInvalidUserName()
        {
            using (var server = TestServer.Create<Startup>())
            {
                var response = await server.CreateRequest("/token").And(x => x.Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("username", "user_invalid"),
                    new KeyValuePair<string, string>("password", "123"),
                    new KeyValuePair<string, string>("grant_type", "password")
                })).PostAsync();

                response.IsSuccessStatusCode.Should().BeFalse();
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
                (await response.Content.ReadAsStringAsync()).Should().NotBeNullOrWhiteSpace();
            }
        }

        [TestMethod]
        public async Task GetTokenWithInvalidPassword()
        {
            using (var server = TestServer.Create<Startup>())
            {
                var response = await server.CreateRequest("/token").And(x => x.Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("username", "user"),
                    new KeyValuePair<string, string>("password", "123_invalid"),
                    new KeyValuePair<string, string>("grant_type", "password")
                })).PostAsync();

                response.IsSuccessStatusCode.Should().BeFalse();
                response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
                (await response.Content.ReadAsStringAsync()).Should().NotBeNullOrWhiteSpace();
            }
        }
    }
}
